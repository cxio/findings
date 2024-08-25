// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v5.26.1
// source: normal.proto

package config

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

// Normal 通用数据包
// 用于封装其它proto编码数据，但同时提供类型标识。
type Normal struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name int32  `protobuf:"varint,1,opt,name=name,proto3" json:"name,omitempty"` // 指令名
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`  // 关联数据（待解码）
}

func (x *Normal) Reset() {
	*x = Normal{}
	if protoimpl.UnsafeEnabled {
		mi := &file_normal_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Normal) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Normal) ProtoMessage() {}

func (x *Normal) ProtoReflect() protoreflect.Message {
	mi := &file_normal_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Normal.ProtoReflect.Descriptor instead.
func (*Normal) Descriptor() ([]byte, []int) {
	return file_normal_proto_rawDescGZIP(), []int{0}
}

func (x *Normal) GetName() int32 {
	if x != nil {
		return x.Name
	}
	return 0
}

func (x *Normal) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

var File_normal_proto protoreflect.FileDescriptor

var file_normal_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x6e, 0x6f, 0x72, 0x6d, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x30,
	0x0a, 0x06, 0x4e, 0x6f, 0x72, 0x6d, 0x61, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04,
	0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61,
	0x42, 0x0b, 0x5a, 0x09, 0x2e, 0x2e, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_normal_proto_rawDescOnce sync.Once
	file_normal_proto_rawDescData = file_normal_proto_rawDesc
)

func file_normal_proto_rawDescGZIP() []byte {
	file_normal_proto_rawDescOnce.Do(func() {
		file_normal_proto_rawDescData = protoimpl.X.CompressGZIP(file_normal_proto_rawDescData)
	})
	return file_normal_proto_rawDescData
}

var file_normal_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_normal_proto_goTypes = []interface{}{
	(*Normal)(nil), // 0: Normal
}
var file_normal_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_normal_proto_init() }
func file_normal_proto_init() {
	if File_normal_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_normal_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Normal); i {
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
			RawDescriptor: file_normal_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_normal_proto_goTypes,
		DependencyIndexes: file_normal_proto_depIdxs,
		MessageInfos:      file_normal_proto_msgTypes,
	}.Build()
	File_normal_proto = out.File
	file_normal_proto_rawDesc = nil
	file_normal_proto_goTypes = nil
	file_normal_proto_depIdxs = nil
}
