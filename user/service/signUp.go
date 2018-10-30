package service

import (
	//"fmt"
	"coinmark/user/model"
	"coinmark/user/util"
	"github.com/rightjoin/aqua"
)

type User struct {
	aqua.RestService `prefix:"user/" root:"/" version:"1"`
	signUp           aqua.POST `url:"/signup"`
	login            aqua.POST `url:"/login"`
	details          aqua.GET  `url:"/details"`
	forgotPassword   aqua.POST `url:"/forgotPassword"`
	verifyCode       aqua.POST `url:"/verifyCode"`
	changePassword   aqua.POST `url:"/changePassword/{token}"`
	signOut          aqua.GET  `url:"/signOut"`
}

//user SignUp
func (usr *User) SignUp(j aqua.Aide) (response interface{}, err error) {
	var (
		reqPayLoad model.User
	)
	if reqPayLoad, err = util.ValidateSignUp(j); err == nil {
		response, err = util.SignUp(reqPayLoad, j)
	}
	return
}

//user Login
func (usr *User) Login(j aqua.Aide) (response interface{}, err error) {
	var (
		validPWD  bool
		user_name string
	)
	if validPWD, user_name, err = util.ValidateLogin(j); err == nil {
		response, err = util.Login(validPWD, user_name, j)
	}
	return
}

// //user Details
// func (usr *User) Details(j aqua.Aide) (
// 	response interface{}, err error) {
// 	response, err = util.Details(j)
// 	return
// }

//user ForgotPassword
func (usr *User) ForgotPassword(j aqua.Aide) (response interface{}, err error) {

	if err = util.ValidateForgotPassword(j); err == nil {
		response, err = util.ForgotPassword(j)
	}

	return

}

// //user VerifyCode
// func (usr *User) VerifyCode(j aqua.Aide) (
// 	response interface{}, err error) {
// 	response, err = util.VerifyCode(j)
// 	return
// }

//user  ChangePassword
func (usr *User) ChangePassword(token string, j aqua.Aide) (response interface{}, err error) {
	var (
		tokenStaus bool
		PWDPload   model.ChangePWD
	)
	if tokenStaus, PWDPload, err = util.ValidateChangePassword(token, j); err == nil {
		if tokenStaus {
			response, err = util.ChangePassword(PWDPload, j)
		}
	}
	return
}

// user SignOut
func (usr *User) SignOut(j aqua.Aide) (response interface{}, err error) {
	var (
		validSession bool
	)
	if validSession, err = util.ValidateSignOut(j); err == nil {
		if validSession {
			response, err = util.SignOut(validSession, j)
		}
	}
	return
}
