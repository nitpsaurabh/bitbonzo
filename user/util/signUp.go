package util

import (
	crypt "coinmark/encrypt_decrypt"
	"coinmark/notification"
	"coinmark/user/model"
	"encoding/json"
	"fmt"
	"github.com/asaskevich/govalidator"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"github.com/rightjoin/aqua"
	"net/http"
	"time"
)

//ValidateSignUp
func ValidateSignUp(j aqua.Aide) (reqPayLoad model.User, err error) {

	j.LoadVars()
	fmt.Println("body ...", j.Body)
	if err = json.Unmarshal([]byte(j.Body), &reqPayLoad); err == nil {
		if _, err = govalidator.ValidateStruct(reqPayLoad); err != nil {
			fmt.Println("validateStruct failed", err)
		}
	}
	return
}

//SignUp
func SignUp(reqPayLoad model.User, j aqua.Aide) (response interface{}, err error) {
	var (
		Conn     *gorm.DB
		userInfo []interface{}
	)

	if Conn, err = dbConn(); err == nil {
		pwd, _ := crypt.Encrypt(reqPayLoad.Password)
		insertSql := `insert into user (first_name, last_name, user_name, email_id,
					 mobile_no, password, sex, country) values 
					 (?, ?, ?, ?, ?, ?, ?, ?);`
		userInfo = append(userInfo, reqPayLoad.FirstName,
			reqPayLoad.LastName, reqPayLoad.UserName, reqPayLoad.EmailID,
			reqPayLoad.MobileNo, pwd, reqPayLoad.Sex, reqPayLoad.Country)
		if err = Conn.Debug().Exec(insertSql, userInfo...).Error; err == nil {
			fmt.Println("successfully updated")
			_, err = GenerateSessionKey(reqPayLoad.UserName, j)
			response = "updated"
		} else {
			fmt.Println("checkout the error", err)
			response = err
		}
	}
	return
}

//ValidateLogin
func ValidateLogin(j aqua.Aide) (validPWD bool, user_name string, err error) {
	j.LoadVars()
	var (
		loginInfo model.LoginInfo
	)
	if err = json.Unmarshal([]byte(j.Body), &loginInfo); err == nil {
		if _, err = govalidator.ValidateStruct(loginInfo); err == nil {
			var (
				Conn     *gorm.DB
				PassWord model.PassWord
			)
			if Conn, err = dbConn(); err == nil {
				selectQry := `Select password from user where user_name = ?`
				if err = Conn.Raw(selectQry, loginInfo.UserName).Find(&PassWord).Error; err == nil {
					validPWD = crypt.ComparePassword(PassWord.PassWord, loginInfo.Password)
					user_name = loginInfo.UserName
				} else {
					fmt.Println("pls input correct info ", err)
				}
			}
		} else {
			fmt.Println("validateStruct failed", err)
		}
	}
	return
}

//Login
func Login(validPWD bool, user_name string, j aqua.Aide) (response interface{}, err error) {
	if validPWD {
		var token string
		if token, err = GenerateSessionKey(user_name, j); err == nil {
			fmt.Println("successfully logged-in")
			response = "logged in"
			addCookie(token, j)
		}
	} else {
		response = "invalid password"
	}
	return
}

type Cnt struct {
	//Count int
	SessionKey string `json:"password" gorm:"column:session_key"`
}

//ValidateSignOut
func ValidateSignOut(j aqua.Aide) (validSession bool, err error) {
	var (
		Conn *gorm.DB
		ct   Cnt
		//count int
	)

	if Conn, err = dbConn(); err == nil {
		sessionKey := j.Request.Header.Get("session_key")
		userName := j.Request.Header.Get("user_name")
		getQry := `Select session_key from user_session where is_active = '1' AND fk_user_name = (?) 
		AND session_key = (?);`
		if err = Conn.Raw(getQry, userName, sessionKey).Find(&ct).Error; err == nil {
			if ct.SessionKey == sessionKey {
				validSession = true
			}
		}
	}
	return
}

//SignOut
func SignOut(validSession bool, j aqua.Aide) (response interface{}, err error) {
	var (
		Conn *gorm.DB
	)
	if validSession {
		if Conn, err = dbConn(); err == nil {
			sessionKey := j.Request.Header.Get("session_key")
			userName := j.Request.Header.Get("user_name")
			rmvSession := `update user_session set is_active = ? where fk_user_name = ? 
			AND session_key = ?;`
			if err = Conn.Debug().Exec(rmvSession, "0", userName, sessionKey).Error; err == nil {
				response = "SuccessFully signOut"
			}
		}
	} else {
		response = "session expired"
	}
	return
}

//ValidateForgotPassword
func ValidateForgotPassword(j aqua.Aide) (err error) {
	j.LoadVars()
	var (
		forgotPWD model.ForgotPassword
		Conn      *gorm.DB
		data      model.ForgotPassword
	)
	if err = json.Unmarshal([]byte(j.Body), &forgotPWD); err == nil {
		if _, err = govalidator.ValidateStruct(forgotPWD); err == nil {
			//check whether the given user id and email exist or not
			if Conn, err = dbConn(); err == nil {
				verifyForgotInfo := `Select user_name, password from user where user_name = ?
				 AND email_id = ?;`
				if err = Conn.Debug().Raw(verifyForgotInfo, forgotPWD.UserName, forgotPWD.EmailID).
					Find(&data).Error; err == nil {
					j.Request.Header.Add("user_name", forgotPWD.UserName)
					j.Request.Header.Add("password", data.Password)
				}
			}
		}
	}
	return
}

//ForgotPassword
func ForgotPassword(j aqua.Aide) (response interface{}, err error) {
	var (
		Conn  *gorm.DB
		token string
	)
	fmt.Println(j.Request)
	UserName := j.Request.Header.Get("user_name")
	fmt.Println(UserName, "7788888")
	Password := j.Request.Header.Get("password")
	expiryTime := time.Now().Add(time.Minute * 15)

	tokenString := UserName + Password + expiryTime.String()
	token, err = crypt.Encrypt(tokenString)
	if Conn, err = dbConn(); err == nil {
		insrtForgotInfo := `insert into forgot_password 
							(fk_user_name, reset_token, expiry_time)
         					values (?, ?, ?) ON DUPLICATE KEY UPDATE 
         					reset_token = ? , expiry_time = ? , is_active = '1'`
		if err = Conn.Exec(insrtForgotInfo, UserName, token, expiryTime, token, expiryTime).
			Error; err == nil {
			fmt.Println("check your mail")
			notification.SendMail(token)
			response = "mail sent"
		} else {
			fmt.Println("err  ", err)
			response = "recheck"
		}
	}
	return
}

//ValidateChange password
func ValidateChangePassword(token1 string, j aqua.Aide) (tokenStatus bool, PWDPload model.ChangePWD, err error) {
	j.LoadVars()
	// postVar := j.PostVar
	// token := postVar["token"]
	token := "$2a$04$/1Y1e8rwDfLxd9I0RF9qYeVx3BzzOpcZ00dNbAqRIkMe8Xn3rbUbu"
	//$2a$04$AAB11/1Tu0bj9mSkr7IekueGOBaXsJiqPMiMTgzbgorHSZqiCsvvq
	fmt.Println(token, "---token---")
	if token != "" {
		fmt.Println("enter into it")
		var (
			Conn *gorm.DB
			info model.ChangePWD
		)
		if Conn, err = dbConn(); err == nil {
			getTokenInfo := `SELECT usr.user_name, 
							  usr.password, 
							  frgt.expiry_time 
							  FROM user as usr
							  JOIN forgot_password as frgt on frgt.fk_user_name = usr.user_name
							  WHERE frgt.reset_token = ? AND frgt.is_active = '1'`
			if err = Conn.Debug().Raw(getTokenInfo, token).Find(&info).Error; err == nil {
				if tokenStatus = validateToken(token, info); tokenStatus {
					//should be redirect to -> insert new password page
					//var PWDPload model.ChangePWD
					if err = json.Unmarshal([]byte(j.Body), &PWDPload); err == nil {
						if _, err = govalidator.ValidateStruct(PWDPload); err == nil {
							fmt.Println("token is active go for change password")
						}
					} else {
						fmt.Println("temper")
					}
				} else {
					fmt.Println(" token expired")
				}
			}
		}
	}

	fmt.Println(err, "-- error ---")
	return
}

//ChangePassword
func ChangePassword(changePWDInfo model.ChangePWD, j aqua.Aide) (
	response interface{}, err error) {
	var (
		Conn *gorm.DB
	)
	if Conn, err = dbConn(); err == nil {
		updatePWD := `UPDATE user SET password = ? 
					 WHERE user_name = ?;`
		pwd, _ := crypt.Encrypt(changePWDInfo.Password)
		if err = Conn.Debug().Exec(updatePWD, pwd, changePWDInfo.UserName).
			Error; err == nil {
			updateTokenStatus := `UPDATE forgot_password SET is_active = '0'
								 WHERE fk_user_name = ?;`
			if err = Conn.Debug().Exec(updateTokenStatus, changePWDInfo.UserName).Error; err == nil {
				fmt.Println("token status changed")
			}
			response = "password updated"

		} else {
			response = "try again"
		}
	}
	return
}

//validateToken
func validateToken(token string, info model.ChangePWD) (isTokenValid bool) {
	tokenString := info.UserName + info.Password + info.ExpiryTime
	isTokenValid = crypt.ComparePassword(token, tokenString)
	return
}

//dbConn
func dbConn() (db *gorm.DB, err error) {
	db, err = gorm.Open("mysql", "root:spatico@/coinmark")
	return
}

//addCookie
func addCookie(token string, j aqua.Aide) {
	if kt, err := j.Request.Cookie("cookie"); err == nil {
		fmt.Println(kt.Value)
	} else {
		fmt.Println("err::", err)
	}
	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{
		Name:     "cookiees",
		Value:    token,
		Expires:  expire,
		HttpOnly: true,
		MaxAge:   1,
	}
	http.SetCookie(j.Response, &cookie)
}

/*todo  generate a new sessionkey  currently we will
use store it in mysql then we will go for redis*/
//GenerateSessionKey
func GenerateSessionKey(user_name string, j aqua.Aide) (token string, err error) {
	var (
		Conn *gorm.DB
		//token       string
		sessionData []interface{}
	)
	if Conn, err = dbConn(); err == nil {
		if token, err = crypt.GenerateRandomString(32); err == nil {
			exp_time := time.Now().Add(time.Minute * 30)
			insertSession := `insert into user_session (
			session_key, fk_user_name,
			location, expiry_time) values(?, ?, ?, ? )`
			sessionData = append(sessionData, token, user_name, "bengaluru", exp_time)
			if err = Conn.Debug().Exec(insertSession, sessionData...).Error; err == nil {
				j.Response.Header().Add("session-key", token)
				j.Response.Header().Add("connection", "keep-alive")
				fmt.Println("err", err)
			}
		} else {
			fmt.Println("session not generated")
		}
	} else {
		fmt.Println("connection not established")
	}
	return
}
