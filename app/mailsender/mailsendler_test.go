package mailsendler

/*import (
	"fmt"
	"log"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Определение интерфейса MailSender, который определяет метод для отправки почты.
type MailSender interface {
	SendMail(addr string, auth smtp.Auth, from string, to []string, msg []byte) error
}

// Mock реализация интерфейса MailSender для тестирования без реальной отправки почты.
type MockMailSender struct {
	Called  bool   // Флаг, указывающий, был ли вызван метод SendMail.
	LastMsg []byte // Содержит последнее отправленное сообщение.
}

// Реализация метода SendMail для MockMailSender.
func (m *MockMailSender) SendMail(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	m.Called = true // Устанавливаем флаг, что метод был вызван.
	m.LastMsg = msg // Сохраняем переданное сообщение.
	return nil      // Возвращаем nil, предполагая, что отправка всегда успешна.
}

// Функция TestMailSendler для юнит-тестирования функции MailSendler.
func TestMailSendler(t *testing.T) {
	mockSender := &MockMailSender{} // Создаем экземпляр MockMailSender для тестов.
	email := "test@example.com"     // Задаем тестовый адрес электронной почты.

	fixedCode := 1234
	// Заменяем чтение файла пароля на фиксированное значение.
	os.WriteFile("db_password.txt", []byte("test_password"), 0644) // Пишем тестовый пароль в файл.
	defer os.Remove("db_password.txt")                             // Удаляем файл после завершения теста.

	MailSendlerCopyForTest(email, mockSender, fixedCode) // Вызываем тестируемую функцию с mockSender.

	// Проверяем, был ли вызван метод SendMail.
	if !mockSender.Called {
		t.Fatal("Expected SendMail to be called, but it wasn't") // Завершаем тест с ошибкой, если SendMail не был вызван.
	}

	expectedMsg := "Код для входа: 1234" // Ожидаемое сообщение.
	// Проверяем, совпадает ли последнее отправленное сообщение с ожидаемым.
	if string(mockSender.LastMsg) != expectedMsg {
		// Если не совпадает, завершаем тест с ошибкой.
		t.Fatalf("Expected message to be '%s', but got '%s'", expectedMsg, mockSender.LastMsg)
	}
}

// Функция MailSendler для отправки кода аутентификации.
// Разница лишь в том, что здесь добавлен мок подменяющий smtp.SendMail
func MailSendlerCopyForTest(input string, sender MailSender, fixedCode int) {
	Authcode_str := strconv.Itoa(fixedCode) // Преобразуем код в строку.

	msg := []byte("Код для входа: " + Authcode_str) // Формируем сообщение с кодом.
	username := "gimaev.vending@ya.ru"              // Указываем адрес отправителя.

	password, err := os.ReadFile("db_password.txt") // Читаем пароль из файла.
	if err != nil {                                 // Проверяем, произошла ли ошибка при чтении файла.
		log.Fatal(err) // Если да, завершаем программу и выводим ошибку.
	}

	host := "smtp.yandex.ru"                                     // Указываем SMTP сервер.
	auth := smtp.PlainAuth("", username, string(password), host) // Создаем объект аутентификации.

	addr := "smtp.yandex.ru:587"   // Полный адрес SMTP сервера с портом.
	from := "gimaev.vending@ya.ru" // Адрес отправителя.
	to := []string{input}          // Список получателей, в данном случае только один.

	err = sender.SendMail(addr, auth, from, to, msg) // Вызываем метод SendMail у переданного sender.
	if err != nil {                                  // Проверяем, произошла ли ошибка.
		fmt.Printf("SendMail: %v", err) // Если да, выводим сообщение об ошибке.
		return                          // Завершаем выполнение функции.
	}
}

func TestIsValidEmail(t *testing.T) {
	// Определяет функцию тестирования для проверки валидности email.

	// Тестируемые случаи
	tests := []struct {
		input    string // Входное значение, которое тестируется
		expected bool   // Ожидаемое логическое значение (true / false)
	}{
		{"test@example.com", true},                  // Корректный email
		{"user.name+tag+sorting@example.com", true}, // Корректный email с тегами
		{"user@sub.example.com", true},              // Корректный поддомен
		{"user@.com", false},                        // Неправильный email (отсутствует локальная часть)
		{"@example.com", false},                     // Неправильный email (отсутствует локальная часть)
		{"user@com", false},                         // Неправильный email (нет точки перед доменным окончанием)
		{"user@.com.", false},                       // Неправильный email (недопустимый домен)
		{"user@com.", false},                        // Неправильный email (домен не может заканчиваться на dot)
		{"user@-example.com", false},                // Неправильный email (домен не может начинаться с "-"
		{"user@example..com", false},                // Неправильный email (двойная точка в домене)
		{"valid@example.com", true},                 // валидный адрес
		{"invalid-email", false},                    // невалидный адрес
		{"@yandex.ru", false},                       // отсутствует имя
		{"user@.ru", false},                         // неправильный домен
		{"test!#$%&'*+/=?^_`{|}~@yandex.ru", false}, // специальные символы
		{"user@subdomain.yandex.ru", true},          // поддомен
		{"user@", false},                            // отсутствует домен
		{"user@ya.ru" + strings.Repeat("a", 500) + "@yandex.ru", false}, // очень длинный адрес
		{"<script>alert('test')</script>@yandex.ru", false},             // возможная XSS атака
		{"test@ya.ru", true}, // другой домен
		{"test@yandexcom", false},
	}

	// Проходит по каждому тестируемому случаю
	for _, test := range tests {
		got := IsValidEmail(test.input) // Получает результат проверки email
		// Сравнивает полученный результат с ожидаемым
		if got != test.expected {
			// Если результат не соответствует ожиданиям, выводит ошибку
			t.Errorf("IsValidEmail(%q) = %v; want %v", test.input, got, test.expected)
		}
	}
}

func TestIsValidCode(t *testing.T) {
	// Определяет функцию тестирования для проверки валидности 4-значного кода.

	// Тестируемые случаи
	tests := []struct {
		input    string // Входное значение, которое тестируется
		expected bool   // Ожидаемое логическое значение (true / false)
	}{
		{"1234", true},   // Корректный код
		{"0000", true},   // Корректный код (нулевой)
		{"5678", true},   // Корректный код
		{"12345", false}, // Неправильный код (длина больше 4)
		{"123", false},   // Неправильный код (длина меньше 4)
		{"12a4", false},  // Неправильный код (буквы присутствуют)
		{"abcd", false},  // Неправильный код (только буквы)
		{"12.34", false}, // Неправильный код (недопустимый символ)
	}

	for _, test := range tests {
		got := IsValidCode(test.input) // Получает результат проверки кода
		// Сравнивает полученный результат с ожидаемым
		if got != test.expected {
			// Если результат не соответствует ожиданиям, выводит ошибку
			t.Errorf("IsValidCode(%q) = %v; want %v", test.input, got, test.expected)
		}
	}
}
*/