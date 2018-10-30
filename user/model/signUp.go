package model

import (
//"time"
)

//user model
// type User struct {
// 	FirstName string `json:"first_name" valid:"required"`
// 	LastName  string `json:"last_name"  valid:"required"`
// 	UserName  string `json:"user_name"  valid:"required"`
// 	EmailID   string `json:"email_id"   valid:"required"`
// 	MobileNo  int64  `json:"mobile_no"  valid:"required"`
// 	Password  string `json:"password"   valid:"required"`
// 	Sex       string `json:"sex" valid:"required"`
// 	Country   string `json:"country" valid:"required"`
// 	IsActive  int    `json:"is_active"`
// }
type User struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name" `
	UserName  string `json:"user_name" `
	EmailID   string `json:"email_id" `
	MobileNo  int64  `json:"mobile_no"`
	Password  string `json:"password"`
	Sex       string `json:"sex" `
	Country   string `json:"country" `
	IsActive  int    `json:"is_active"`
}

//login
type LoginInfo struct {
	UserName string `json:"user_name" `
	EmailID  string `json:"email_id" `
	Password string `json:"password" valid:"required"`
}

//ForgotPassword
type ForgotPassword struct {
	UserName string `json:"user_name" valid:"required" gorm:"column:user_name"`
	EmailID  string `json:"email_id" valid:"required" gorm:"column:email_id"`
	Password string `json:"password" gorm:"column:password"`
}

//
type PassWord struct {
	PassWord string `json:"password" gorm:"column:password"`
}

//change password info
type ChangePWD struct {
	UserName   string `json:"user_name" gorm:"column:user_name"`
	Password   string `json:"password" gorm:"column:password"`
	ExpiryTime string `json:"expiry_time" gorm:"column:expiry_time"`
}
