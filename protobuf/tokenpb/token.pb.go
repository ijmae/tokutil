// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.2
// source: token.proto

package tokenpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Plan struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id                    string   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name                  string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	MaxDeviceLogin        int32    `protobuf:"varint,3,opt,name=maxDeviceLogin,proto3" json:"maxDeviceLogin,omitempty"`
	MaxDeviceStream       int32    `protobuf:"varint,4,opt,name=maxDeviceStream,proto3" json:"maxDeviceStream,omitempty"`
	ExpiredAt             int32    `protobuf:"varint,5,opt,name=expiredAt,proto3" json:"expiredAt,omitempty"`
	ContentIds            []string `protobuf:"bytes,6,rep,name=contentIds,proto3" json:"contentIds,omitempty"`
	IsForceMaxDeviceLogin int32    `protobuf:"varint,7,opt,name=isForceMaxDeviceLogin,proto3" json:"isForceMaxDeviceLogin,omitempty"`
	Platforms             []int32  `protobuf:"varint,8,rep,packed,name=platforms,proto3" json:"platforms,omitempty"`
	KplusId               string   `protobuf:"bytes,9,opt,name=kplusId,proto3" json:"kplusId,omitempty"`
	DeviceId              string   `protobuf:"bytes,10,opt,name=deviceId,proto3" json:"deviceId,omitempty"`
	IsAutoRenew           int32    `protobuf:"varint,11,opt,name=isAutoRenew,proto3" json:"isAutoRenew,omitempty"`
}

func (x *Plan) Reset() {
	*x = Plan{}
	if protoimpl.UnsafeEnabled {
		mi := &file_token_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Plan) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Plan) ProtoMessage() {}

func (x *Plan) ProtoReflect() protoreflect.Message {
	mi := &file_token_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Plan.ProtoReflect.Descriptor instead.
func (*Plan) Descriptor() ([]byte, []int) {
	return file_token_proto_rawDescGZIP(), []int{0}
}

func (x *Plan) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Plan) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Plan) GetMaxDeviceLogin() int32 {
	if x != nil {
		return x.MaxDeviceLogin
	}
	return 0
}

func (x *Plan) GetMaxDeviceStream() int32 {
	if x != nil {
		return x.MaxDeviceStream
	}
	return 0
}

func (x *Plan) GetExpiredAt() int32 {
	if x != nil {
		return x.ExpiredAt
	}
	return 0
}

func (x *Plan) GetContentIds() []string {
	if x != nil {
		return x.ContentIds
	}
	return nil
}

func (x *Plan) GetIsForceMaxDeviceLogin() int32 {
	if x != nil {
		return x.IsForceMaxDeviceLogin
	}
	return 0
}

func (x *Plan) GetPlatforms() []int32 {
	if x != nil {
		return x.Platforms
	}
	return nil
}

func (x *Plan) GetKplusId() string {
	if x != nil {
		return x.KplusId
	}
	return ""
}

func (x *Plan) GetDeviceId() string {
	if x != nil {
		return x.DeviceId
	}
	return ""
}

func (x *Plan) GetIsAutoRenew() int32 {
	if x != nil {
		return x.IsAutoRenew
	}
	return 0
}

type AccessToken struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Iat             int32    `protobuf:"varint,1,opt,name=iat,proto3" json:"iat,omitempty"`
	Exp             int32    `protobuf:"varint,2,opt,name=exp,proto3" json:"exp,omitempty"`
	IsAuthenticated int32    `protobuf:"varint,3,opt,name=isAuthenticated,proto3" json:"isAuthenticated,omitempty"`
	Uid             string   `protobuf:"bytes,4,opt,name=uid,proto3" json:"uid,omitempty"`
	Username        string   `protobuf:"bytes,5,opt,name=username,proto3" json:"username,omitempty"`
	DeviceId        string   `protobuf:"bytes,6,opt,name=deviceId,proto3" json:"deviceId,omitempty"`
	DeviceName      string   `protobuf:"bytes,7,opt,name=deviceName,proto3" json:"deviceName,omitempty"`
	VersionCode     int32    `protobuf:"varint,8,opt,name=versionCode,proto3" json:"versionCode,omitempty"`
	Platform        int32    `protobuf:"varint,9,opt,name=platform,proto3" json:"platform,omitempty"`
	DeviceInfo      string   `protobuf:"bytes,10,opt,name=deviceInfo,proto3" json:"deviceInfo,omitempty"`
	UserAgent       string   `protobuf:"bytes,11,opt,name=userAgent,proto3" json:"userAgent,omitempty"`
	DtId            int32    `protobuf:"varint,12,opt,name=dtId,proto3" json:"dtId,omitempty"`
	SpId            string   `protobuf:"bytes,13,opt,name=spId,proto3" json:"spId,omitempty"`
	AuthType        string   `protobuf:"bytes,14,opt,name=authType,proto3" json:"authType,omitempty"`
	Plans           []*Plan  `protobuf:"bytes,15,rep,name=plans,proto3" json:"plans,omitempty"`
	ClientId        string   `protobuf:"bytes,16,opt,name=clientId,proto3" json:"clientId,omitempty"`
	HasPackage      int32    `protobuf:"varint,17,opt,name=hasPackage,proto3" json:"hasPackage,omitempty"`
	IsPaid          int32    `protobuf:"varint,18,opt,name=isPaid,proto3" json:"isPaid,omitempty"`
	Ip              string   `protobuf:"bytes,19,opt,name=ip,proto3" json:"ip,omitempty"`
	IsFromVN        int32    `protobuf:"varint,20,opt,name=isFromVN,proto3" json:"isFromVN,omitempty"`
	City            string   `protobuf:"bytes,21,opt,name=city,proto3" json:"city,omitempty"`
	Zone            int32    `protobuf:"varint,22,opt,name=zone,proto3" json:"zone,omitempty"`
	Isp             string   `protobuf:"bytes,23,opt,name=isp,proto3" json:"isp,omitempty"`
	UserCollections []string `protobuf:"bytes,24,rep,name=userCollections,proto3" json:"userCollections,omitempty"`
	Jti             string   `protobuf:"bytes,25,opt,name=jti,proto3" json:"jti,omitempty"`
	OsVersion       string   `protobuf:"bytes,26,opt,name=osVersion,proto3" json:"osVersion,omitempty"`
	AppVersion      string   `protobuf:"bytes,27,opt,name=appVersion,proto3" json:"appVersion,omitempty"`
	DisplayName     string   `protobuf:"bytes,28,opt,name=displayName,proto3" json:"displayName,omitempty"`
}

func (x *AccessToken) Reset() {
	*x = AccessToken{}
	if protoimpl.UnsafeEnabled {
		mi := &file_token_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessToken) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessToken) ProtoMessage() {}

func (x *AccessToken) ProtoReflect() protoreflect.Message {
	mi := &file_token_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessToken.ProtoReflect.Descriptor instead.
func (*AccessToken) Descriptor() ([]byte, []int) {
	return file_token_proto_rawDescGZIP(), []int{1}
}

func (x *AccessToken) GetIat() int32 {
	if x != nil {
		return x.Iat
	}
	return 0
}

func (x *AccessToken) GetExp() int32 {
	if x != nil {
		return x.Exp
	}
	return 0
}

func (x *AccessToken) GetIsAuthenticated() int32 {
	if x != nil {
		return x.IsAuthenticated
	}
	return 0
}

func (x *AccessToken) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *AccessToken) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *AccessToken) GetDeviceId() string {
	if x != nil {
		return x.DeviceId
	}
	return ""
}

func (x *AccessToken) GetDeviceName() string {
	if x != nil {
		return x.DeviceName
	}
	return ""
}

func (x *AccessToken) GetVersionCode() int32 {
	if x != nil {
		return x.VersionCode
	}
	return 0
}

func (x *AccessToken) GetPlatform() int32 {
	if x != nil {
		return x.Platform
	}
	return 0
}

func (x *AccessToken) GetDeviceInfo() string {
	if x != nil {
		return x.DeviceInfo
	}
	return ""
}

func (x *AccessToken) GetUserAgent() string {
	if x != nil {
		return x.UserAgent
	}
	return ""
}

func (x *AccessToken) GetDtId() int32 {
	if x != nil {
		return x.DtId
	}
	return 0
}

func (x *AccessToken) GetSpId() string {
	if x != nil {
		return x.SpId
	}
	return ""
}

func (x *AccessToken) GetAuthType() string {
	if x != nil {
		return x.AuthType
	}
	return ""
}

func (x *AccessToken) GetPlans() []*Plan {
	if x != nil {
		return x.Plans
	}
	return nil
}

func (x *AccessToken) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *AccessToken) GetHasPackage() int32 {
	if x != nil {
		return x.HasPackage
	}
	return 0
}

func (x *AccessToken) GetIsPaid() int32 {
	if x != nil {
		return x.IsPaid
	}
	return 0
}

func (x *AccessToken) GetIp() string {
	if x != nil {
		return x.Ip
	}
	return ""
}

func (x *AccessToken) GetIsFromVN() int32 {
	if x != nil {
		return x.IsFromVN
	}
	return 0
}

func (x *AccessToken) GetCity() string {
	if x != nil {
		return x.City
	}
	return ""
}

func (x *AccessToken) GetZone() int32 {
	if x != nil {
		return x.Zone
	}
	return 0
}

func (x *AccessToken) GetIsp() string {
	if x != nil {
		return x.Isp
	}
	return ""
}

func (x *AccessToken) GetUserCollections() []string {
	if x != nil {
		return x.UserCollections
	}
	return nil
}

func (x *AccessToken) GetJti() string {
	if x != nil {
		return x.Jti
	}
	return ""
}

func (x *AccessToken) GetOsVersion() string {
	if x != nil {
		return x.OsVersion
	}
	return ""
}

func (x *AccessToken) GetAppVersion() string {
	if x != nil {
		return x.AppVersion
	}
	return ""
}

func (x *AccessToken) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

type RefreshToken struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Jti string `protobuf:"bytes,1,opt,name=jti,proto3" json:"jti,omitempty"`
	Did string `protobuf:"bytes,2,opt,name=did,proto3" json:"did,omitempty"`
	Uid string `protobuf:"bytes,3,opt,name=uid,proto3" json:"uid,omitempty"`
	Iat int32  `protobuf:"varint,4,opt,name=iat,proto3" json:"iat,omitempty"`
	Exp int32  `protobuf:"varint,5,opt,name=exp,proto3" json:"exp,omitempty"`
}

func (x *RefreshToken) Reset() {
	*x = RefreshToken{}
	if protoimpl.UnsafeEnabled {
		mi := &file_token_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RefreshToken) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RefreshToken) ProtoMessage() {}

func (x *RefreshToken) ProtoReflect() protoreflect.Message {
	mi := &file_token_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RefreshToken.ProtoReflect.Descriptor instead.
func (*RefreshToken) Descriptor() ([]byte, []int) {
	return file_token_proto_rawDescGZIP(), []int{2}
}

func (x *RefreshToken) GetJti() string {
	if x != nil {
		return x.Jti
	}
	return ""
}

func (x *RefreshToken) GetDid() string {
	if x != nil {
		return x.Did
	}
	return ""
}

func (x *RefreshToken) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *RefreshToken) GetIat() int32 {
	if x != nil {
		return x.Iat
	}
	return 0
}

func (x *RefreshToken) GetExp() int32 {
	if x != nil {
		return x.Exp
	}
	return 0
}

var File_token_proto protoreflect.FileDescriptor

var file_token_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x74,
	0x6f, 0x6b, 0x65, 0x6e, 0x70, 0x62, 0x22, 0xe6, 0x02, 0x0a, 0x04, 0x50, 0x6c, 0x61, 0x6e, 0x12,
	0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12,
	0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x26, 0x0a, 0x0e, 0x6d, 0x61, 0x78, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
	0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0e, 0x6d, 0x61, 0x78,
	0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x12, 0x28, 0x0a, 0x0f, 0x6d,
	0x61, 0x78, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x0f, 0x6d, 0x61, 0x78, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x53,
	0x74, 0x72, 0x65, 0x61, 0x6d, 0x12, 0x1c, 0x0a, 0x09, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64,
	0x41, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65,
	0x64, 0x41, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x49, 0x64,
	0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x49, 0x64, 0x73, 0x12, 0x34, 0x0a, 0x15, 0x69, 0x73, 0x46, 0x6f, 0x72, 0x63, 0x65, 0x4d, 0x61,
	0x78, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x15, 0x69, 0x73, 0x46, 0x6f, 0x72, 0x63, 0x65, 0x4d, 0x61, 0x78, 0x44, 0x65,
	0x76, 0x69, 0x63, 0x65, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x70, 0x6c, 0x61,
	0x74, 0x66, 0x6f, 0x72, 0x6d, 0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x05, 0x52, 0x09, 0x70, 0x6c,
	0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x6b, 0x70, 0x6c, 0x75, 0x73,
	0x49, 0x64, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6b, 0x70, 0x6c, 0x75, 0x73, 0x49,
	0x64, 0x12, 0x1a, 0x0a, 0x08, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x49, 0x64, 0x18, 0x0a, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x49, 0x64, 0x12, 0x20, 0x0a,
	0x0b, 0x69, 0x73, 0x41, 0x75, 0x74, 0x6f, 0x52, 0x65, 0x6e, 0x65, 0x77, 0x18, 0x0b, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x0b, 0x69, 0x73, 0x41, 0x75, 0x74, 0x6f, 0x52, 0x65, 0x6e, 0x65, 0x77, 0x22,
	0x80, 0x06, 0x0a, 0x0b, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12,
	0x10, 0x0a, 0x03, 0x69, 0x61, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x69, 0x61,
	0x74, 0x12, 0x10, 0x0a, 0x03, 0x65, 0x78, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03,
	0x65, 0x78, 0x70, 0x12, 0x28, 0x0a, 0x0f, 0x69, 0x73, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0f, 0x69, 0x73,
	0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x12, 0x10, 0x0a,
	0x03, 0x75, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12,
	0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x64,
	0x65, 0x76, 0x69, 0x63, 0x65, 0x49, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x64,
	0x65, 0x76, 0x69, 0x63, 0x65, 0x49, 0x64, 0x12, 0x1e, 0x0a, 0x0a, 0x64, 0x65, 0x76, 0x69, 0x63,
	0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x64, 0x65, 0x76,
	0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0b, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x6c, 0x61,
	0x74, 0x66, 0x6f, 0x72, 0x6d, 0x18, 0x09, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x70, 0x6c, 0x61,
	0x74, 0x66, 0x6f, 0x72, 0x6d, 0x12, 0x1e, 0x0a, 0x0a, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x49,
	0x6e, 0x66, 0x6f, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x64, 0x65, 0x76, 0x69, 0x63,
	0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x1c, 0x0a, 0x09, 0x75, 0x73, 0x65, 0x72, 0x41, 0x67, 0x65,
	0x6e, 0x74, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x75, 0x73, 0x65, 0x72, 0x41, 0x67,
	0x65, 0x6e, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x74, 0x49, 0x64, 0x18, 0x0c, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x04, 0x64, 0x74, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x70, 0x49, 0x64, 0x18,
	0x0d, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x73, 0x70, 0x49, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x61,
	0x75, 0x74, 0x68, 0x54, 0x79, 0x70, 0x65, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x61,
	0x75, 0x74, 0x68, 0x54, 0x79, 0x70, 0x65, 0x12, 0x23, 0x0a, 0x05, 0x70, 0x6c, 0x61, 0x6e, 0x73,
	0x18, 0x0f, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x70, 0x62,
	0x2e, 0x50, 0x6c, 0x61, 0x6e, 0x52, 0x05, 0x70, 0x6c, 0x61, 0x6e, 0x73, 0x12, 0x1a, 0x0a, 0x08,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x18, 0x10, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x1e, 0x0a, 0x0a, 0x68, 0x61, 0x73, 0x50,
	0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x18, 0x11, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0a, 0x68, 0x61,
	0x73, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x69, 0x73, 0x50, 0x61,
	0x69, 0x64, 0x18, 0x12, 0x20, 0x01, 0x28, 0x05, 0x52, 0x06, 0x69, 0x73, 0x50, 0x61, 0x69, 0x64,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x13, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x70,
	0x12, 0x1a, 0x0a, 0x08, 0x69, 0x73, 0x46, 0x72, 0x6f, 0x6d, 0x56, 0x4e, 0x18, 0x14, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x08, 0x69, 0x73, 0x46, 0x72, 0x6f, 0x6d, 0x56, 0x4e, 0x12, 0x12, 0x0a, 0x04,
	0x63, 0x69, 0x74, 0x79, 0x18, 0x15, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x63, 0x69, 0x74, 0x79,
	0x12, 0x12, 0x0a, 0x04, 0x7a, 0x6f, 0x6e, 0x65, 0x18, 0x16, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04,
	0x7a, 0x6f, 0x6e, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x69, 0x73, 0x70, 0x18, 0x17, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x69, 0x73, 0x70, 0x12, 0x28, 0x0a, 0x0f, 0x75, 0x73, 0x65, 0x72, 0x43, 0x6f,
	0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x18, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x0f, 0x75, 0x73, 0x65, 0x72, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x12, 0x10, 0x0a, 0x03, 0x6a, 0x74, 0x69, 0x18, 0x19, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6a,
	0x74, 0x69, 0x12, 0x1c, 0x0a, 0x09, 0x6f, 0x73, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x1a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6f, 0x73, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x12, 0x1e, 0x0a, 0x0a, 0x61, 0x70, 0x70, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x1b,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x61, 0x70, 0x70, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x12, 0x20, 0x0a, 0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x18,
	0x1c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61,
	0x6d, 0x65, 0x22, 0x68, 0x0a, 0x0c, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x12, 0x10, 0x0a, 0x03, 0x6a, 0x74, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6a, 0x74, 0x69, 0x12, 0x10, 0x0a, 0x03, 0x64, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x64, 0x69, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x69, 0x64, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x69, 0x61, 0x74, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x69, 0x61, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x65, 0x78,
	0x70, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x65, 0x78, 0x70, 0x42, 0x12, 0x5a, 0x10,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x70, 0x62,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_token_proto_rawDescOnce sync.Once
	file_token_proto_rawDescData = file_token_proto_rawDesc
)

func file_token_proto_rawDescGZIP() []byte {
	file_token_proto_rawDescOnce.Do(func() {
		file_token_proto_rawDescData = protoimpl.X.CompressGZIP(file_token_proto_rawDescData)
	})
	return file_token_proto_rawDescData
}

var file_token_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_token_proto_goTypes = []interface{}{
	(*Plan)(nil),         // 0: tokenpb.Plan
	(*AccessToken)(nil),  // 1: tokenpb.AccessToken
	(*RefreshToken)(nil), // 2: tokenpb.RefreshToken
}
var file_token_proto_depIdxs = []int32{
	0, // 0: tokenpb.AccessToken.plans:type_name -> tokenpb.Plan
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_token_proto_init() }
func file_token_proto_init() {
	if File_token_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_token_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Plan); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_token_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessToken); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_token_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RefreshToken); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_token_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_token_proto_goTypes,
		DependencyIndexes: file_token_proto_depIdxs,
		MessageInfos:      file_token_proto_msgTypes,
	}.Build()
	File_token_proto = out.File
	file_token_proto_rawDesc = nil
	file_token_proto_goTypes = nil
	file_token_proto_depIdxs = nil
}
