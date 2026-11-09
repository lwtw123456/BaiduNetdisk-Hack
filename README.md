# BaiduNetdisk-Hack
Electron 程序逆向练习，这种程序其实没啥逆向的意义，因为核心能力以及鉴权基本都在服务端。

不过也实现了一些实用本地功能的解锁，包括视频倍速播放、智能字幕、文稿的复制和导出等，启动时也不会再有推荐升级 VIP 的弹窗。

程序还是有不少防护的，没有深入分析 native 层，但是简单分析就找到了 asar 的完整性检查、dll 的完整性检查、反 dll 注入、遍历文件夹删除未签名 dll、VMP 保护核心函数等。

但是攻击面仍然很好找，打 BaiduNetdiskUnite.exe。遍历文件夹删除未签名 dll 这一点尤其好玩，已经被程序加载的 dll 根本删不掉，所以这防护等于没做。

需要注意的点是，百度网盘加载自带的老版本 VC runtime，所以直接用新版本的 MSVC 编译会出问题，在 cmake 里已经做了兼容。

至于服务端功能，就别想了。高速下载嘛。。。嗯，能持续一秒。

## Credits

DLL Proxy 部分基于 **AheadLibEx**：

```text
https://github.com/i1tao/AheadLibEx
```

Author: i1tao

## Disclaimer

本项目仅用于 **逆向工程技术研究与学习交流**。

## License

MIT License
