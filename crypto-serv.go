package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
)

var templates = template.Must(template.ParseFiles("edit.html", "view.html", "decrypt.html"))

func main() {
	fmt.Printf("Server is running on port 8080")
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/view/", viewHandler)
	http.HandleFunc("/create/", createHandler)
	http.HandleFunc("/save/", saveHandler)
	http.HandleFunc("/decrypt/", decryptHandler)
	http.ListenAndServe(":"+os.Getenv("PORT"), nil)
}

//HTTP Index Handler
func indexHandler(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	fmt.Printf("[+] Index page accessed by %s\n", ip)
	files, _ := ioutil.ReadDir("./messages/")
	fmt.Fprintf(w, "<style>body{font-family: courier;}</style><h1>MIS 445 Crypto Go Server</h1>")
	for _, f := range files {
		if f.Name()[len(f.Name())-4:] == ".txt" {
			fmt.Fprintf(w, "<a href='/view/%s'>%s</a><br /><br />", f.Name()[:len(f.Name())-4], f.Name()[:len(f.Name())-4])
		}
	}
	fmt.Fprintf(w, "<br /><a href='/create/'><button>Create New</button></a>")
}

//HTTP view Handler
func viewHandler(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	fmt.Printf("[+] View page accessed by %s\n", ip)
	title := r.URL.Path[len("/view/"):]
	p, err := loadPage(title)
	if err != nil {
		fmt.Printf("[-] Tried accessing non existant page: %s\n", r.URL.Path[1:])
		http.Redirect(w, r, "/edit/"+title, http.StatusFound)
		return
	}
	renderTemplate(w, "view", p)
}

//HTTP edit handler
func createHandler(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	fmt.Printf("[+] Edit page accessed by %s\n", ip)
	title := r.URL.Path[len("/create/"):]
	p, err := loadPage(title)
	if err != nil {
		p = &Page{Title: title}
	}
	renderTemplate(w, "edit", p)
}

//HTTP save handler
func saveHandler(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	fmt.Printf("[+] Save page accessed by %s\n", ip)
	title := r.FormValue("msg-title")
	body, _ := encrypt([]byte(padKey(r.FormValue("init-key"))), []byte(r.FormValue("body")))
	p := &Page{Title: title, Msg: []byte(body)}
	p.save()
	http.Redirect(w, r, "/view/"+title, http.StatusFound)
}

//HTTP decrypt handler
func decryptHandler(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	fmt.Printf("[+] Decrypt Page Accessed by %s\n", ip)
	title := r.URL.Path[len("/decrypt/"):]
	p, _ := loadPage(title)
	fmt.Printf("[$] Key used: %s\n", r.FormValue("d-key"))
	decryptedMsg, err := decrypt([]byte(padKey(r.FormValue("d-key"))), p.Msg)
	if err != nil {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Printf("[-] Invalid key entered by %s\n", ip)
		fmt.Fprintf(w, "<style>body{text-align: center;font-family: currier;} </style><h1>Invalid key used</h1><a href='/'><button>Return Home</button></a>")
		return
	}
	fmt.Fprintf(w, "<style>body{text-align: center;font-family: currier;} </style><h1>Decrypted Message</h1><p>%s</p><a href='/'><button>Home</button></a>", decryptedMsg)

}

//Handles template rendering
func renderTemplate(w http.ResponseWriter, tmpl string, p *Page) {
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

//Ensure Key is right number of chars
func padKey(key string) string {
	length := len(key)
	if length == 16 || length == 24 || length == 32 {
		return key
	} else if length < 16 {
		padLen := 16 - length
		padding := strings.Repeat("f", padLen)
		return key + padding
	} else if length < 24 {
		padLen := 24 - length
		padding := strings.Repeat("f", padLen)
		return key + padding
	} else if length < 32 {
		padLen := 32 - length
		padding := strings.Repeat("f", padLen)
		return key + padding
	} else {
		return key[:32]
	}
}

//Struct defining page
type Page struct {
	Title string
	Msg   []byte
}

//Save page
func (p *Page) save() error {
	filename := p.Title + ".txt"
	return ioutil.WriteFile("messages/"+filename, p.Msg, 0600)
}

//Load page
func loadPage(title string) (*Page, error) {
	filename := title + ".txt"
	body, err := ioutil.ReadFile("messages/" + filename)
	if err != nil {
		return nil, err
	}
	return &Page{Title: title, Msg: body}, nil
}

//Encrypt function. Takes a key and text to be encrypted. Returns encrypted text and err
func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

//Decrypt function. Takes in a key and encrypted text. Returns the decrypted text and err
func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(text) < aes.BlockSize {
		return nil, errors.New("cipher text too short")
	}

	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}
