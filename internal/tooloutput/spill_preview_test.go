package tooloutput

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
 "unicode/utf8"
)

func TestFormatPersistedFromFileBoundedUnicode(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"large-output")
 content:=strings.Repeat("中文原件\n",100000)
 if err:=os.WriteFile(path,[]byte(content),0600);err!=nil{t.Fatal(err)}
 notice:=FormatPersistedFromFile(path,len(content),1200)
 if len(notice)>1200||!utf8.ValidString(notice)||!strings.Contains(notice,path){t.Fatalf("invalid preview: bytes=%d valid=%v",len(notice),utf8.ValidString(notice))}
 original,err:=os.ReadFile(path);if err!=nil||string(original)!=content{t.Fatal("original changed",err)}
}
