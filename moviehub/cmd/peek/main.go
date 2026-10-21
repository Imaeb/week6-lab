package main

// peek แอบดูไส้ในตั๋ว JWT ว่าเขียนอะไรไว้ และถ้าแก้ตัวอักษรในตั๋ว พนักงานตรวจตั๋วจับได้ไหม
//
//   go run ./cmd/peek          ออกตั๋วตัวอย่างแล้วทดลองให้ดูทีละขั้น
//   go run ./cmd/peek <ตั๋ว>    แอบดูตั๋วจริงที่ได้จาก POST /api/auth/login (ไม่ตรวจลายเซ็น)

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "os"
    "strings"
    "time"

    "moviehub/auth"
)

func main() {
    if len(os.Args) > 1 {
        if err := peek(os.Args[1]); err != nil {
            fmt.Println("อ่านตั๋วไม่ออก:", err)
            os.Exit(1)
        }
        return
    }

    iss := &auth.Issuer{Secret: []byte("peek-demo-secret-ใช้ทดลองเท่านั้น-0123456789"), TTL: time.Hour}
    token, err := iss.Issue(7, "member")
    if err != nil {
        fmt.Println("ออกตั๋วไม่ได้:", err)
        os.Exit(1)
    }

    // 1) ตั๋วมี 3 ท่อน คั่นด้วยจุด: header.payload.signature
    fmt.Println("ตั๋ว:", token)

    // 2) header กับ payload เป็นแค่ base64url ใครก็ถอดอ่านได้ ไม่ต้องมีกุญแจ
    peek(token)

    // 3) ตั๋วจริง พนักงานตรวจตั๋วให้ผ่าน
    report("ตั๋วจริง", iss, token)

    // 4) แก้ role ใน payload เป็น admin แต่ใช้ลายเซ็นเดิม ลายเซ็นไม่ตรงจึงถูกปฏิเสธ
    report("ตั๋วปลอม role=admin", iss, withRole(token, "admin"))

    // 5) ตั๋วจริง แต่ตรวจด้วยกุญแจคนละดอก (เช่น server ที่ตั้ง JWT_SECRET อื่น) ก็ไม่ผ่าน
    other := &auth.Issuer{Secret: []byte("กุญแจดอกอื่นของอีกเครื่อง-0123456789abcdef"), TTL: time.Hour}
    report("กุญแจคนละดอก", other, token)
}

// peek ถอด header กับ payload ออกมาพิมพ์โดยไม่ตรวจลายเซ็น อ่านได้ไม่ได้แปลว่าเป็นตั๋วจริง
func peek(token string) error {
    parts := strings.Split(strings.TrimSpace(token), ".")
    if len(parts) != 3 {
        return fmt.Errorf("ตั๋ว JWT ต้องมี 3 ท่อนคั่นด้วยจุด แต่อันนี้มี %d ท่อน", len(parts))
    }
    var claims map[string]any
    for i, name := range []string{"header", "payload"} {
        raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[i], "="))
        if err != nil {
            return fmt.Errorf("ถอด %s ไม่ได้: %w", name, err)
        }
        var pretty bytes.Buffer
        if err := json.Indent(&pretty, raw, "", "  "); err != nil {
            return fmt.Errorf("%s ไม่ใช่ JSON: %w", name, err)
        }
        fmt.Printf("%s:\n%s\n", name, pretty.String())
        if name == "payload" {
            json.Unmarshal(raw, &claims)
        }
    }
    // iat กับ exp เป็นวินาทีนับจาก 1 ม.ค. 1970 แปลงให้อ่านง่าย
    for _, k := range []string{"iat", "exp"} {
        if v, ok := claims[k].(float64); ok {
            fmt.Printf("%s = %s\n", k, time.Unix(int64(v), 0).Format("2006-01-02 15:04:05 MST"))
        }
    }
    fmt.Println("signature:", parts[2], "(ตรวจได้เฉพาะคนที่มี JWT_SECRET)")
    return nil
}

// withRole สร้างตั๋วปลอม: แก้ role ใน payload แต่ยังใช้ header กับลายเซ็นของตั๋วเดิม
func withRole(token, role string) string {
    parts := strings.Split(token, ".")
    raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
    var claims map[string]any
    json.Unmarshal(raw, &claims)
    claims["role"] = role
    b, _ := json.Marshal(claims)
    parts[1] = base64.RawURLEncoding.EncodeToString(b)
    return strings.Join(parts, ".")
}

// report ให้พนักงานตรวจตั๋ว (Parse) ตรวจแล้วพิมพ์ผล
func report(label string, iss *auth.Issuer, token string) {
    id, role, err := iss.Parse(token)
    if err != nil {
        fmt.Printf("%s: ไม่ผ่าน (%v)\n", label, err)
        return
    }
    fmt.Printf("%s: ผ่าน สมาชิก %d บทบาท %s\n", label, id, role)
}
