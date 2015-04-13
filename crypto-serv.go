package main 

import(
	"fmt"
	"crypto/cipher"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"html/template"
	//"regexp"
)

var templates = template.Must(template.ParseFiles("edit.html", "view.html", "decrypt.html"))


func main() {
	fmt.Printf("Server is running on port 8080")
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/view/", viewHandler)
	http.HandleFunc("/create/", createHandler)
	http.HandleFunc("/save/", saveHandler)
	http.HandleFunc("/decrypt/", decryptHandler)
	http.ListenAndServe(":8080", nil)

	/*
	key := []byte("sssouThdaKoTa412")

	plaintext := []byte("Secret Message to be encrypted!")
	fmt.Printf("Text before encoding: %s\n", plaintext)
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%0x\n", ciphertext)
	result, err := decrypt(key, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", result)
	*/
}

//HTTP Index Handler
func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Index page accessed\n")
	files, _ := ioutil.ReadDir("./")
	fmt.Fprintf(w, "<h1>MIS 445 Crypto Go Server</h1>")
	for _, f := range files {
		if f.Name()[len(f.Name())-4:] == ".txt"{
			fmt.Fprintf(w, "<a href='/view/%s'>%s</a><br />", f.Name()[:len(f.Name())-4], f.Name()[:len(f.Name())-4])
		}
	}
	fmt.Fprintf(w, "<br /><a href='/create/'><button>Create New</button></a>")
}

//HTTP view Handler
func viewHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("View page accessed\n")
	title := r.URL.Path[len("/view/"):]
	p, err := loadPage(title)
	if err != nil {
		fmt.Printf("Tried accessing non existant page: %s\n", r.URL.Path[1:])
		http.Redirect(w, r, "/edit/"+title, http.StatusFound)
		return
	}
	renderTemplate(w, "view", p)
}

//HTTP edit handler
func createHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Edit page accessed\n")
	title := r.URL.Path[len("/create/"):]
	p,err := loadPage(title)
	if err != nil {
		p = &Page{Title: title}
	}
	renderTemplate(w, "edit", p)
}

//HTTP save handler
func saveHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Save page accessed\n")
	title := r.FormValue("msg-title")
	body, _ := encrypt([]byte(r.FormValue("init-key")), []byte(r.FormValue("body")))
	p := &Page{Title: title, Msg: []byte(body)}
	p.save()
	http.Redirect(w,r, "/view/"+title, http.StatusFound)
}

//HTTP decrypt handler
func decryptHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("MADE IT")
	title := r.URL.Path[len("/decrypt/"):]
	fmt.Printf("GOT TITLE")
	p,_ := loadPage(title)
	fmt.Printf("%s", r.FormValue("d-key"))
	decryptedMsg, _ := decrypt([]byte(r.FormValue("d-key")), p.Msg)
	fmt.Fprintf(w, "<h1>Decrypted Message</h1><p>%s</p><a href='/'><button>Home</button></a>", decryptedMsg)

}

//Handles template rendering
func renderTemplate(w http.ResponseWriter, tmpl string, p *Page) {
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

//Struct defining page
type Page struct {
	Title string
	Msg []byte
}

//Save page 
func (p *Page) save() error {
	filename := p.Title + ".txt"
	return ioutil.WriteFile(filename, p.Msg, 0600)
}

//Load page 
func loadPage(title string) (*Page, error) {
	filename := title + ".txt"
	body,err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return &Page{Title: title, Msg: body}, nil
}

//Encrypt function. Takes a key and text to be encrypted. Returns encrypted text and err
func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _,err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

//Decrypt function. Takes in a key and encrypted text. Returns the decrypted text and err
func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
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
		panic(err)
	}
	return data, nil
}