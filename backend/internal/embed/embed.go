package embed

import "embed"

// StaticFiles - 嵌入的前端静态文件目录
//
// 使用 Go 1.16+ 的 embed 指令将前端构建产物打包到二进制文件中
// 实现单端口架构：Go Backend 同时提供 REST API 和 Vue.js 前端
//
// 构建前端:
//
//	cd frontend && npm run build
//
// 构建产物会输出到 ../backend/web/ 目录
// 该目录通过 //go:embed 指令嵌入到二进制中
//
//go:embed web/*
var StaticFiles embed.FS
