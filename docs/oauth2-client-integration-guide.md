# WeSpringAuthServer OAuth2 Client 集成指南

> 🎯 **目标**: 让您的前端应用（以 Next.js 14 + TypeScript 为例）快速集成 WeSpringAuthServer 作为 OAuth2 Client

## 📖 概述

本指南将帮助您将前端应用配置为 OAuth2 Client，实现用户通过 WeSpringAuthServer 进行统一登录认证。我们以 Next.js 14 + TypeScript 技术栈为例，展示完整的集成流程。

### OAuth2 角色说明
- **Authorization Server**: WeSpringAuthServer（认证服务器）
- **Client**: 您的前端应用（本指南重点）
- **Resource Server**: 后端 API 服务（参见 [资源服务器集成指南](./resource-server-integration-guide.md)）

## ⚡ 快速开始

### 第一步：安装依赖

在您的 Next.js 项目中添加 OAuth2 相关依赖：

```bash
npm install next-auth@beta @auth/core
# 或使用 yarn
yarn add next-auth@beta @auth/core
```

> 💡 **注意**: 我们使用 next-auth v5 (beta) 版本，它对 Next.js 14 App Router 有更好的支持

### 第二步：配置环境变量

在项目根目录创建或更新 `.env.local` 文件：

```bash
# OAuth2 配置
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=your-secret-key-here

# WeSpringAuthServer 配置
OAUTH_AUTHORIZATION_URL=http://localhost:9000/oauth2/authorize
OAUTH_TOKEN_URL=http://localhost:9000/oauth2/token
OAUTH_USERINFO_URL=http://localhost:9000/userinfo
OAUTH_JWKS_URL=http://localhost:9000/oauth2/jwks

# OAuth2 Client 配置
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URI=http://localhost:3000/api/auth/callback/wespring
```

> ⚠️ **重要**: 请将这些配置值替换为您在 WeSpringAuthServer 中注册的实际 Client 信息

### 第三步：创建 Auth.js 配置

创建 `lib/auth.ts` 文件：

```typescript
import type { NextAuthConfig } from "next-auth"
import { JWT } from "next-auth/jwt"

// 扩展 JWT 类型以包含我们需要的字段
declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string
    refreshToken?: string
    authorities?: string[]
    groups?: string[]
    expiresAt?: number
  }
}

// 扩展 Session 类型
declare module "next-auth" {
  interface Session {
    accessToken?: string
    authorities?: string[]
    groups?: string[]
    error?: string
  }
}

export const authConfig: NextAuthConfig = {
  providers: [
    {
      id: "wespring",
      name: "WeSpring Auth Server",
      type: "oauth",
      authorization: {
        url: process.env.OAUTH_AUTHORIZATION_URL!,
        params: {
          scope: "openid profile email authorities groups",
          response_type: "code",
        },
      },
      token: process.env.OAUTH_TOKEN_URL!,
      userinfo: process.env.OAUTH_USERINFO_URL!,
      clientId: process.env.OAUTH_CLIENT_ID!,
      clientSecret: process.env.OAUTH_CLIENT_SECRET!,
      // 用户信息映射
      profile(profile) {
        console.log("Profile from WeSpringAuthServer:", profile)
        return {
          id: profile.sub,
          name: profile.name || profile.preferred_username,
          email: profile.email,
          // 保存权限和组信息
          authorities: profile.authorities || [],
          groups: profile.groups || [],
        }
      },
    },
  ],
  pages: {
    signIn: "/login",
    error: "/login", // 错误时重定向到登录页
  },
  callbacks: {
    // JWT 回调 - 处理令牌
    async jwt({ token, account, profile }) {
      console.log("JWT callback triggered")
      
      // 初次登录时保存 OAuth2 令牌信息
      if (account && profile) {
        console.log("Initial login - saving tokens")
        token.accessToken = account.access_token
        token.refreshToken = account.refresh_token
        token.authorities = profile.authorities || []
        token.groups = profile.groups || []
        // 计算过期时间
        token.expiresAt = Date.now() + (account.expires_in || 3600) * 1000
      }
      
      // 检查令牌是否即将过期（提前5分钟刷新）
      if (token.expiresAt && Date.now() > token.expiresAt - 300000) {
        console.log("Token expiring soon, attempting refresh")
        return await refreshAccessToken(token)
      }
      
      return token
    },
    
    // Session 回调 - 构建客户端 session
    async session({ session, token }) {
      console.log("Session callback triggered")
      
      if (token.error) {
        console.error("Token error:", token.error)
        session.error = token.error as string
      }
      
      // 将令牌信息传递给客户端
      session.accessToken = token.accessToken as string
      session.authorities = token.authorities as string[]
      session.groups = token.groups as string[]
      
      return session
    },
    
    // 授权回调 - 控制页面访问权限
    authorized({ request, auth }) {
      const { pathname } = request.nextUrl
      
      // 公开页面
      if (pathname === "/login" || pathname.startsWith("/api/auth/")) {
        return true
      }
      
      // 需要登录的页面
      return !!auth?.user
    },
  },
  // 启用调试模式（开发环境）
  debug: process.env.NODE_ENV === "development",
}

// 刷新访问令牌
async function refreshAccessToken(token: JWT): Promise<JWT> {
  try {
    console.log("Refreshing access token...")
    
    const response = await fetch(process.env.OAUTH_TOKEN_URL!, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: token.refreshToken!,
        client_id: process.env.OAUTH_CLIENT_ID!,
        client_secret: process.env.OAUTH_CLIENT_SECRET!,
      }),
    })

    const refreshedTokens = await response.json()

    if (!response.ok) {
      console.error("Token refresh failed:", refreshedTokens)
      throw new Error("Token refresh failed")
    }

    console.log("Token refreshed successfully")
    return {
      ...token,
      accessToken: refreshedTokens.access_token,
      refreshToken: refreshedTokens.refresh_token ?? token.refreshToken,
      expiresAt: Date.now() + refreshedTokens.expires_in * 1000,
    }
  } catch (error) {
    console.error("Error refreshing access token:", error)
    return {
      ...token,
      error: "RefreshAccessTokenError",
    }
  }
}
```

### 第四步：配置 Auth.js Route Handler

创建 `app/api/auth/[...nextauth]/route.ts` 文件：

```typescript
import NextAuth from "next-auth"
import { authConfig } from "@/lib/auth"

const handler = NextAuth(authConfig)

export { handler as GET, handler as POST }
```

### 第五步：创建认证中间件

创建 `middleware.ts` 文件（项目根目录）：

```typescript
import { NextRequest } from "next/server"
import { auth } from "@/lib/auth"

export default auth((req: NextRequest & { auth: any }) => {
  const { pathname } = req.nextUrl
  
  // 记录访问日志
  console.log(`${req.method} ${pathname} - Auth:`, !!req.auth)
  
  // 如果用户未登录且访问受保护页面，重定向到登录页
  if (!req.auth && !pathname.startsWith("/login") && !pathname.startsWith("/api/auth/")) {
    const loginUrl = new URL("/login", req.url)
    loginUrl.searchParams.set("callbackUrl", pathname)
    return Response.redirect(loginUrl)
  }
})

export const config = {
  matcher: [
    // 排除静态文件和API认证路由
    "/((?!api/auth|_next/static|_next/image|favicon.ico).*)",
  ],
}
```

### 第六步：创建登录页面

创建 `app/login/page.tsx` 文件：

```typescript
"use client"

import { signIn, getSession } from "next-auth/react"
import { useSearchParams, useRouter } from "next/navigation"
import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"

export default function LoginPage() {
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const searchParams = useSearchParams()
  const router = useRouter()
  
  const callbackUrl = searchParams.get("callbackUrl") || "/"
  const errorParam = searchParams.get("error")

  useEffect(() => {
    // 显示 OAuth 错误信息
    if (errorParam) {
      setError(getErrorMessage(errorParam))
    }
  }, [errorParam])

  const handleSignIn = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      console.log("Starting OAuth2 sign in...")
      
      const result = await signIn("wespring", {
        callbackUrl,
        redirect: false, // 手动处理重定向
      })
      
      if (result?.error) {
        console.error("Sign in error:", result.error)
        setError(getErrorMessage(result.error))
      } else if (result?.url) {
        // 登录成功，手动重定向
        console.log("Sign in successful, redirecting to:", result.url)
        router.push(result.url)
      } else {
        // 检查是否已经登录
        const session = await getSession()
        if (session) {
          console.log("Already signed in, redirecting to:", callbackUrl)
          router.push(callbackUrl)
        }
      }
    } catch (error) {
      console.error("Login error:", error)
      setError("登录过程中发生未知错误，请重试")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-bold">登录</CardTitle>
          <CardDescription>
            使用 WeSpringAuthServer 统一认证登录
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          
          <Button
            onClick={handleSignIn}
            disabled={isLoading}
            className="w-full"
            size="lg"
          >
            {isLoading ? "登录中..." : "登录"}
          </Button>
          
          <div className="text-sm text-gray-500 text-center">
            点击登录将跳转到 WeSpringAuthServer 进行身份验证
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function getErrorMessage(error: string): string {
  const errorMessages: Record<string, string> = {
    Configuration: "服务器配置错误，请联系管理员",
    AccessDenied: "访问被拒绝，您可能没有相应权限",
    Verification: "验证失败，请重试",
    Default: "登录失败，请检查您的凭据并重试",
  }
  
  return errorMessages[error] || errorMessages.Default
}
```

### 第七步：创建 Session Provider

创建 `components/providers/session-provider.tsx` 文件：

```typescript
"use client"

import { SessionProvider } from "next-auth/react"
import { ReactNode } from "react"

interface Props {
  children: ReactNode
}

export default function AuthSessionProvider({ children }: Props) {
  return <SessionProvider>{children}</SessionProvider>
}
```

### 第八步：更新根布局

更新 `app/layout.tsx` 文件：

```typescript
import type { Metadata } from "next"
import AuthSessionProvider from "@/components/providers/session-provider"
import "./globals.css"

export const metadata: Metadata = {
  title: "管理后台",
  description: "基于 WeSpringAuthServer 的管理后台系统",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="zh-CN">
      <body>
        <AuthSessionProvider>
          {children}
        </AuthSessionProvider>
      </body>
    </html>
  )
}
```

## 🔐 使用认证信息

### 在服务端组件中使用

```typescript
import { auth } from "@/lib/auth"
import { redirect } from "next/navigation"

export default async function ProtectedPage() {
  const session = await auth()
  
  if (!session) {
    redirect("/login")
  }
  
  return (
    <div>
      <h1>受保护的页面</h1>
      <p>欢迎，{session.user?.name}！</p>
      <p>您的权限：{session.authorities?.join(", ")}</p>
      <p>您的组：{session.groups?.join(", ")}</p>
    </div>
  )
}
```

### 在客户端组件中使用

```typescript
"use client"

import { useSession, signOut } from "next-auth/react"
import { Button } from "@/components/ui/button"

export default function UserProfile() {
  const { data: session, status } = useSession()
  
  if (status === "loading") {
    return <p>加载中...</p>
  }
  
  if (status === "unauthenticated") {
    return <p>请先登录</p>
  }
  
  return (
    <div className="space-y-4">
      <h2>用户信息</h2>
      <div>
        <p><strong>用户名:</strong> {session?.user?.name}</p>
        <p><strong>邮箱:</strong> {session?.user?.email}</p>
        <p><strong>权限:</strong> {session?.authorities?.join(", ")}</p>
        <p><strong>组:</strong> {session?.groups?.join(", ")}</p>
      </div>
      
      <Button onClick={() => signOut()}>
        退出登录
      </Button>
    </div>
  )
}
```

### 权限控制 Hook

创建 `hooks/use-permissions.ts` 文件：

```typescript
"use client"

import { useSession } from "next-auth/react"
import { useMemo } from "react"

export function usePermissions() {
  const { data: session } = useSession()
  
  const permissions = useMemo(() => {
    if (!session?.authorities) return new Set<string>()
    return new Set(session.authorities)
  }, [session?.authorities])
  
  const groups = useMemo(() => {
    if (!session?.groups) return new Set<string>()
    return new Set(session.groups)
  }, [session?.groups])
  
  const hasPermission = (permission: string): boolean => {
    return permissions.has(permission)
  }
  
  const hasAnyPermission = (...requiredPermissions: string[]): boolean => {
    return requiredPermissions.some(permission => permissions.has(permission))
  }
  
  const hasAllPermissions = (...requiredPermissions: string[]): boolean => {
    return requiredPermissions.every(permission => permissions.has(permission))
  }
  
  const hasRole = (role: string): boolean => {
    return permissions.has(role)
  }
  
  const isInGroup = (group: string): boolean => {
    return groups.has(group) || groups.has(`GROUP_${group}`)
  }
  
  return {
    permissions: Array.from(permissions),
    groups: Array.from(groups),
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    hasRole,
    isInGroup,
    isAdmin: hasRole("ROLE_ADMIN"),
    isAuthenticated: !!session,
  }
}
```

### 权限控制组件

创建 `components/auth/permission-guard.tsx` 文件：

```typescript
"use client"

import { usePermissions } from "@/hooks/use-permissions"
import { ReactNode } from "react"

interface PermissionGuardProps {
  children: ReactNode
  permission?: string
  permissions?: string[]
  requireAll?: boolean
  role?: string
  group?: string
  fallback?: ReactNode
}

export default function PermissionGuard({
  children,
  permission,
  permissions = [],
  requireAll = false,
  role,
  group,
  fallback = null,
}: PermissionGuardProps) {
  const { hasPermission, hasAnyPermission, hasAllPermissions, hasRole, isInGroup } = usePermissions()
  
  let hasAccess = true
  if (permission && !hasPermission(permission)) {
    hasAccess = false
  }
  
  // 检查多个权限
  if (permissions.length > 0) {
    if (requireAll) {
      hasAccess = hasAllPermissions(...permissions)
    } else {
      hasAccess = hasAnyPermission(...permissions)
    }
  }
  
  // 检查角色
  if (role && !hasRole(role)) {
    hasAccess = false
  }
  
  // 检查组
  if (group && !isInGroup(group)) {
    hasAccess = false
  }
  
  return hasAccess ? <>{children}</> : <>{fallback}</>
}
```

## 🔌 调用受保护的 API

### 创建 API 客户端

创建 `lib/api-client.ts` 文件：

```typescript
import { getSession } from "next-auth/react"

class ApiClient {
  private baseURL: string
  
  constructor(baseURL: string = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080/api") {
    this.baseURL = baseURL
  }
  
  private async getAuthHeaders(): Promise<HeadersInit> {
    const session = await getSession()
    
    if (!session?.accessToken) {
      throw new Error("No access token available")
    }
    
    return {
      "Authorization": `Bearer ${session.accessToken}`,
      "Content-Type": "application/json",
    }
  }
  
  async get<T>(endpoint: string): Promise<T> {
    const headers = await this.getAuthHeaders()
    
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      method: "GET",
      headers,
    })
    
    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${response.statusText}`)
    }
    
    return response.json()
  }
  
  async post<T>(endpoint: string, data: any): Promise<T> {
    const headers = await this.getAuthHeaders()
    
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      method: "POST",
      headers,
      body: JSON.stringify(data),
    })
    
    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${response.statusText}`)
    }
    
    return response.json()
  }
  
  async put<T>(endpoint: string, data: any): Promise<T> {
    const headers = await this.getAuthHeaders()
    
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      method: "PUT",
      headers,
      body: JSON.stringify(data),
    })
    
    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${response.statusText}`)
    }
    
    return response.json()
  }
  
  async delete<T>(endpoint: string): Promise<T> {
    const headers = await this.getAuthHeaders()
    
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      method: "DELETE",
      headers,
    })
    
    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${response.statusText}`)
    }
    
    return response.json()
  }
}

export const apiClient = new ApiClient()
```

### 使用示例

```typescript
"use client"

import { useState, useEffect } from "react"
import { apiClient } from "@/lib/api-client"
import { usePermissions } from "@/hooks/use-permissions"

interface User {
  id: string
  name: string
  email: string
}

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { hasPermission } = usePermissions()
  
  useEffect(() => {
    if (hasPermission("Users_Read")) {
      loadUsers()
    } else {
      setError("您没有查看用户列表的权限")
      setLoading(false)
    }
  }, [hasPermission])
  
  const loadUsers = async () => {
    try {
      setLoading(true)
      const data = await apiClient.get<User[]>("/users")
      setUsers(data)
    } catch (err) {
      setError("加载用户列表失败")
      console.error("Load users error:", err)
    } finally {
      setLoading(false)
    }
  }
  
  if (loading) return <div>加载中...</div>
  if (error) return <div>错误: {error}</div>
  
  return (
    <div>
      <h1>用户列表</h1>
      <ul>
        {users.map(user => (
          <li key={user.id}>
            {user.name} ({user.email})
          </li>
        ))}
      </ul>
    </div>
  )
}
```

## 🔧 高级配置

### 令牌刷新策略

配置自动令牌刷新（在 `lib/auth.ts` 中已实现）：

```typescript
// JWT 回调中的令牌刷新逻辑
if (token.expiresAt && Date.now() > token.expiresAt - 300000) {
  console.log("Token expiring soon, attempting refresh")
  return await refreshAccessToken(token)
}
```

### 错误处理和重试机制

创建 `lib/auth-error-handler.ts` 文件：

```typescript
import { signOut } from "next-auth/react"

export class AuthError extends Error {
  constructor(
    message: string,
    public code: string,
    public status?: number
  ) {
    super(message)
    this.name = "AuthError"
  }
}

export async function handleAuthError(error: any) {
  console.error("Auth error:", error)
  
  // 令牌过期或无效，强制重新登录
  if (error.status === 401 || error.code === "RefreshAccessTokenError") {
    console.log("Token invalid, signing out...")
    await signOut({ callbackUrl: "/login" })
    return
  }
  
  // 权限不足
  if (error.status === 403) {
    console.log("Access denied")
    // 可以显示权限不足的提示或跳转到无权限页面
    return
  }
  
  // 其他错误
  throw error
}
```

### 开发环境调试

在 `next.config.js` 中启用详细日志：

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    NEXTAUTH_DEBUG: process.env.NODE_ENV === 'development' ? 'true' : 'false',
  },
  // 其他配置...
}

module.exports = nextConfig
```

## 🧪 测试集成

### 1. 启动应用

```bash
npm run dev
```

### 2. 测试登录流程

1. 访问 `http://localhost:3000`
2. 应该自动重定向到登录页面
3. 点击登录按钮，跳转到 WeSpringAuthServer
4. 完成认证后回调到应用
5. 验证用户信息和权限是否正确加载

### 3. 测试权限控制

创建测试页面验证权限控制是否正常工作：

```typescript
// app/test/permissions/page.tsx
import PermissionGuard from "@/components/auth/permission-guard"

export default function PermissionsTestPage() {
  return (
    <div className="space-y-4">
      <h1>权限测试页面</h1>
      
      <PermissionGuard permission="Users_Read">
        <div className="p-4 bg-green-100 border border-green-400 rounded">
          ✅ 您有 Users_Read 权限
        </div>
      </PermissionGuard>
      
      <PermissionGuard 
        permission="Users_Read" 
        fallback={
          <div className="p-4 bg-red-100 border border-red-400 rounded">
            ❌ 您没有 Users_Read 权限
          </div>
        }
      />
      
      <PermissionGuard role="ROLE_ADMIN">
        <div className="p-4 bg-blue-100 border border-blue-400 rounded">
          👑 您是管理员
        </div>
      </PermissionGuard>
    </div>
  )
}
```

## ❓ 常见问题

### Q: 登录后无法获取用户信息？
A: 检查以下配置：
1. `OAUTH_USERINFO_URL` 是否正确
2. OAuth2 scope 是否包含必要的信息
3. WeSpringAuthServer 的 userinfo 端点是否正常工作

### Q: 权限信息丢失？
A: 确保：
1. OAuth2 scope 包含 `authorities` 和 `groups`
2. JWT 回调正确保存了权限信息
3. Session 回调正确传递了权限到客户端

### Q: 令牌刷新失败？
A: 检查：
1. `refresh_token` 是否正确保存
2. WeSpringAuthServer 的令牌刷新端点配置
3. 客户端密钥是否正确

### Q: 中间件重定向循环？
A: 确保：
1. 中间件配置的 matcher 正确排除了认证相关路径
2. 登录页面和 API 路由不需要认证
3. 检查 `NEXTAUTH_URL` 配置是否正确

### Q: 开发环境 HTTPS 问题？
A: 如果 WeSpringAuthServer 使用 HTTPS 而开发环境使用 HTTP：
1. 在 WeSpringAuthServer 中允许 HTTP 回调 URL（仅开发环境）
2. 或使用开发环境 HTTPS 证书

## 📚 更多资源

- [Auth.js 官方文档](https://authjs.dev/)
- [Next.js 认证指南](https://nextjs.org/docs/app/building-your-application/authentication)
- [OAuth2 标准规范](https://tools.ietf.org/html/rfc6749)
- [WeSpringAuthServer 资源服务器集成](./resource-server-integration-guide.md)

---

🎉 **恭喜！** 您的 Next.js 应用现在已经成功集成了 WeSpringAuthServer 作为 OAuth2 Client！