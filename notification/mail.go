package notification

import (
	"fmt"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	//"log"
)

func SendMail(token string) {
	fmt.Println("---- ", token)
	from := mail.NewEmail("Saurabh", "skcse03@gmail.com")
	to := mail.NewEmail("pb", "saurabh@coinmark.in")
	plainTextContent := "coinMark password Reset" + token
	htmlContent := "<strong>and easy to do anywhere, even with Go</strong>" + token
	subject := "reset password"
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient("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")
	if response, err := client.Send(message); err == nil {
		fmt.Println(response)
	}
}
