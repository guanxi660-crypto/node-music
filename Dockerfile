# DeployCloud 部署镜像 —— nzws-js(Node HTTP + WebSocket 服务)
#
# 为什么用 alpine:
#   - 体积小,免费档 512MB 内存下更省开销
#   - @grpc/grpc-js、systeminformation、ws 都是纯 JS,无 native 依赖,alpine 完全够用
#
# 为什么用 npm ci --omit=optional:
#   - optionalDependencies 里的 node-pty 是 native 模块(musl 下需要编译工具链)
#   - 它只用于"远程 shell exec"这个边缘功能;核心的哪吒上报 + 订阅生成不依赖它
#   - 跳过它可避免构建失败/超时;若日后需要 shell 功能,改用 node:20-slim + build-essential
FROM node:20-alpine

WORKDIR /app

# 先复制依赖清单,利用 Docker 层缓存加速后续构建
COPY package.json package-lock.json ./
RUN npm ci --omit=optional

# 复制应用源码(含 index.js、index.html 伪装页、Procfile)
COPY index.js index.html Procfile ./

# $PORT 由 DeployCloud 平台注入(默认 3000),httpServer.listen(PORT) 会监听它
ENV NODE_ENV=production
EXPOSE 3000

# 常驻服务:监听 $PORT,健康检查通过后接流量
CMD ["node", "index.js"]
