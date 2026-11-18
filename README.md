# pairwise-dockerfile-guard

镜像构建交给业务团队后，容器基线就开始松动：Dockerfile 默认 root 用户；基础镜像用 `latest`，无法复现；构建参数里塞入密钥，留在镜像层；`apt-get` 不清理缓存，镜像膨胀；`curl | sh` 直接执行远程脚本；setuid 二进制没有剥离；capabilities 全量保留；健康检查缺失；多阶段构建把构建工具带进运行镜像；`.dockerignore` 没排除 `.git`；镜像只用 tag 不用 digest；入口脚本权限过宽。security/dockerfile_guard.py 是核心，tests/test_dockerfile_guard.py 15个红。要修的是：非 root 用户；基础镜像固定 digest；构建密钥不落层；包缓存清理；禁止管道执行；剥离 setuid；capabilities 最小化；健康检查；多阶段隔离；dockerignore；digest 校验；入口权限。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
