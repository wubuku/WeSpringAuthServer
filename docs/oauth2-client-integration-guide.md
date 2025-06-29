# WeSpringAuthServer OAuth2 Client 集成指南

> 🎯 **目标**: 让您的前端应用（以 RuiChuangQi-AI admin-console 为例）快速集成 WeSpringAuthServer 作为 OAuth2 Client

## 📖 概述

本指南将帮助您将现有的前端应用改造为 OAuth2 Client，实现用户通过 WeSpringAuthServer 进行统一登录认证。我们以实际项目 **RuiChuangQi-AI/src/admin-console**（Next.js 14 + TypeScript）为例，展示从模拟认证到 OAuth2 认证的完整迁移流程。

### OAuth2 角色说明
- **Authorization Server**: WeSpringAuthServer（认证服务器）
- **Client**: 您的前端应用（本指南重点）
- **Resource Server**: 后端 API 服务（参见 [资源服务器集成指南](./resource-server-integration-guide.md)）

### 当前项目分析

根据对目标项目的分析，当前架构特点：
- 🔧 **技术栈**: Next.js 14 + TypeScript + Tailwind CSS + SWR
- 🔐 **认证方式**: 自定义 AuthContext + localStorage（模拟认证）
- 👥 **用户角色**: 6种复杂角色体系 (`headquarters_admin`, `distributor_admin`, 等)
- 🛡️ **权限系统**: 基于资源-动作模式的细粒度权限控制
- 📦 **状态管理**: React Context API
- 🎨 **UI组件**: 基于 Radix UI 的自定义组件库

## ⚡ 快速开始

### 第一步：安装 OAuth2 依赖

由于项目已使用自定义认证，我们选择轻量级方案：

```bash
npm install @types/jsonwebtoken
# 或使用 yarn  
yarn add @types/jsonwebtoken
```

> 💡 **设计决策**: 考虑到项目已有成熟的认证架构，我们采用**渐进式迁移**策略，保留现有的 AuthContext 结构，仅替换底层认证逻辑

### 第二步：配置环境变量

更新项目根目录的 `.env.local` 文件（已存在），添加 OAuth2 配置：

```bash
# 保留现有配置
NEXT_PUBLIC_API_MOCKING=enabled
NEXT_PUBLIC_API_URL=http://localhost:3000/api
NEXT_PUBLIC_BAIDU_MAP_API_KEY=YOUR_BAIDU_MAP_API_KEY

# 新增 OAuth2 配置
NEXT_PUBLIC_OAUTH_ENABLED=true
NEXT_PUBLIC_WESPRING_AUTH_URL=http://localhost:9000
NEXT_PUBLIC_OAUTH_CLIENT_ID=admin-console-client
NEXT_PUBLIC_OAUTH_REDIRECT_URI=http://localhost:3000/auth/callback

# 服务端 OAuth2 配置（敏感信息）
OAUTH_CLIENT_SECRET=your-client-secret-here
OAUTH_JWKS_URL=http://localhost:9000/oauth2/jwks
```

更新 `.env.local.example` 文件，为其他开发者提供配置模板：

```bash
# 保留原有内容，新增以下配置：

# OAuth2 Configuration - 是否启用 OAuth2 认证（false 时使用模拟认证）
NEXT_PUBLIC_OAUTH_ENABLED=false
NEXT_PUBLIC_WESPRING_AUTH_URL=http://localhost:9000
NEXT_PUBLIC_OAUTH_CLIENT_ID=admin-console-client
NEXT_PUBLIC_OAUTH_REDIRECT_URI=http://localhost:3000/auth/callback

# Server-side OAuth2 secrets (仅生产环境需要)
OAUTH_CLIENT_SECRET=your-client-secret-here
OAUTH_JWKS_URL=http://localhost:9000/oauth2/jwks
```

> 💡 **设计优势**: 使用环境变量控制认证模式，开发环境可继续使用模拟认证，生产环境启用 OAuth2

### 第三步：创建 OAuth2 服务

创建 `lib/oauth2-service.ts` 文件，实现 OAuth2 认证逻辑：

```typescript
import { User, UserRole } from '@/types';

// OAuth2 认证服务
export class OAuth2Service {
  private baseUrl: string;
  private clientId: string;
  private redirectUri: string;
  private clientSecret: string;

  constructor() {
    this.baseUrl = process.env.NEXT_PUBLIC_WESPRING_AUTH_URL || 'http://localhost:9000';
    this.clientId = process.env.NEXT_PUBLIC_OAUTH_CLIENT_ID || 'admin-console-client';
    this.redirectUri = process.env.NEXT_PUBLIC_OAUTH_REDIRECT_URI || 'http://localhost:3000/auth/callback';
    this.clientSecret = process.env.OAUTH_CLIENT_SECRET || '';
  }

  // 生成授权 URL
  getAuthorizationUrl(state?: string): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: 'openid profile email authorities groups',
      state: state || Math.random().toString(36).substring(7),
    });

    return `${this.baseUrl}/oauth2/authorize?${params.toString()}`;
  }

  // 交换授权码获取令牌
  async exchangeCodeForTokens(code: string): Promise<{
    access_token: string;
    refresh_token: string;
    expires_in: number;
    id_token?: string;
  }> {
    const response = await fetch(`${this.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: this.clientId,
        client_secret: this.clientSecret,
        redirect_uri: this.redirectUri,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Token exchange failed: ${error}`);
    }

    return response.json();
  }

  // 获取用户信息
  async getUserInfo(accessToken: string): Promise<{
    sub: string;
    name: string;
    email: string;
    authorities: string[];
    groups: string[];
    [key: string]: any;
  }> {
    const response = await fetch(`${this.baseUrl}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user info');
    }

    return response.json();
  }

  // 刷新访问令牌
  async refreshAccessToken(refreshToken: string): Promise<{
    access_token: string;
    refresh_token?: string;
    expires_in: number;
  }> {
    const response = await fetch(`${this.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      }),
    });

    if (!response.ok) {
      throw new Error('Token refresh failed');
    }

    return response.json();
  }

  // 转换 OAuth2 用户信息为应用用户对象
  mapOAuth2UserToAppUser(oauth2User: any, accessToken: string): User {
    // 从权限中推断用户角色
    const role = this.mapAuthoritiesToRole(oauth2User.authorities || []);
    
    return {
      id: oauth2User.sub,
      name: oauth2User.name || oauth2User.preferred_username,
      phone: oauth2User.phone || '', // 可能需要从其他地方获取
      email: oauth2User.email,
      role,
      active: true,
      avatarUrl: oauth2User.picture,
      
      // OAuth2 特有字段
      authorities: oauth2User.authorities || [],
      groups: oauth2User.groups || [],
      accessToken,
      
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    } as User & { authorities: string[]; groups: string[]; accessToken: string };
  }

  // 从权限映射到用户角色
  private mapAuthoritiesToRole(authorities: string[]): UserRole {
    // 根据权限推断角色，优先级从高到低
    if (authorities.includes('ROLE_ADMIN') || authorities.includes('ROLE_HEADQUARTERS_ADMIN')) {
      return 'headquarters_admin';
    }
    if (authorities.includes('ROLE_DISTRIBUTOR_ADMIN')) {
      return 'distributor_admin';
    }
    if (authorities.includes('ROLE_DISTRIBUTOR_EMPLOYEE')) {
      return 'distributor_employee';
    }
    if (authorities.includes('ROLE_STORE_ADMIN')) {
      return 'store_admin';
    }
    if (authorities.includes('ROLE_CONSULTANT')) {
      return 'consultant';
    }
    if (authorities.includes('ROLE_CUSTOMER')) {
      return 'customer';
    }
    
    // 默认角色
    return 'customer';
  }

  // 撤销令牌（登出）
  async revokeToken(token: string): Promise<void> {
    try {
      await fetch(`${this.baseUrl}/oauth2/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          token,
          client_id: this.clientId,
          client_secret: this.clientSecret,
        }),
      });
    } catch (error) {
      console.error('Token revocation failed:', error);
      // 不抛出错误，因为本地清理仍然有效
    }
  }
}

export const oauth2Service = new OAuth2Service();
```

### 第四步：更新认证上下文

修改现有的 `contexts/auth-context.tsx` 文件，添加 OAuth2 支持：

```typescript
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User } from '@/types';
import { oauth2Service } from '@/lib/oauth2-service';

// 扩展用户类型以包含 OAuth2 信息
interface ExtendedUser extends User {
  authorities?: string[];
  groups?: string[];
  accessToken?: string;
  refreshToken?: string;
  tokenExpiresAt?: number;
}

// 认证上下文类型
type AuthContextType = {
  user: ExtendedUser | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<boolean>;
  loginWithOAuth2: () => Promise<void>;
  logout: () => void;
  refreshToken: () => Promise<boolean>;
};

// 创建认证上下文
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// 认证提供者组件
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<ExtendedUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // 检查是否启用 OAuth2
  const isOAuth2Enabled = process.env.NEXT_PUBLIC_OAUTH_ENABLED === 'true';

  // 检查本地存储中是否有用户数据
  useEffect(() => {
    const initializeAuth = async () => {
      setIsLoading(true);
      
      try {
        const storedUser = localStorage.getItem("user");
        if (storedUser) {
          const parsedUser = JSON.parse(storedUser) as ExtendedUser;
          
          // 如果是 OAuth2 用户，检查令牌是否过期
          if (parsedUser.accessToken && parsedUser.tokenExpiresAt) {
            const now = Date.now();
            const expiresAt = parsedUser.tokenExpiresAt;
            
            // 如果令牌即将过期（提前5分钟）
            if (now > expiresAt - 300000) {
              console.log("Token expiring soon, attempting refresh...");
              const refreshSuccess = await refreshTokenSilently(parsedUser);
              if (!refreshSuccess) {
                console.log("Token refresh failed, clearing user data");
                localStorage.removeItem("user");
                setUser(null);
                return;
              }
            }
          }
          
          setUser(parsedUser);
        }
      } catch (error) {
        console.error("Failed to initialize auth:", error);
        localStorage.removeItem("user");
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, []);

  // 静默刷新令牌
  const refreshTokenSilently = async (currentUser: ExtendedUser): Promise<boolean> => {
    if (!currentUser.refreshToken) return false;

    try {
      const tokenResponse = await oauth2Service.refreshAccessToken(currentUser.refreshToken);
      const updatedUser = {
        ...currentUser,
        accessToken: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token || currentUser.refreshToken,
        tokenExpiresAt: Date.now() + tokenResponse.expires_in * 1000,
      };
      
      setUser(updatedUser);
      localStorage.setItem("user", JSON.stringify(updatedUser));
      return true;
    } catch (error) {
      console.error("Silent token refresh failed:", error);
      return false;
    }
  };

  // 模拟登录（兼容现有逻辑）
  const login = async (username: string, password: string): Promise<boolean> => {
    if (isOAuth2Enabled) {
      console.warn("OAuth2 is enabled, use loginWithOAuth2() instead");
      return false;
    }

    setIsLoading(true);
    
    try {
      // 保留原有的模拟登录逻辑
      await new Promise(resolve => setTimeout(resolve, 800));
      
      let mockUser: User | null = null;
      
      if (username === "admin" && password === "password") {
        mockUser = {
          id: "1",
          name: "总部管理员",
          phone: "13800000001",
          email: "admin@example.com",
          role: "headquarters_admin",
          active: true,
          partyType: "Company",
          partyId: "HQ-001",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
      } else if (username === "distributor" && password === "password") {
        mockUser = {
          id: "2",
          name: "经销商管理员",
          phone: "13800000002",
          email: "distributor@example.com",
          role: "distributor_admin",
          active: true,
          partyType: "DistributorOrganization",
          partyId: "DIST-001",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
      } else if (username === "store" && password === "password") {
        mockUser = {
          id: "3",
          name: "门店管理员",
          phone: "13800000003",
          email: "store@example.com",
          role: "store_admin",
          active: true,
          partyType: "Store",
          partyId: "STORE-001",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
      }
      
      if (mockUser) {
        setUser(mockUser);
        localStorage.setItem("user", JSON.stringify(mockUser));
        return true;
      }
      
      return false;
    } catch (error) {
      console.error("Login error:", error);
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  // OAuth2 登录
  const loginWithOAuth2 = async (): Promise<void> => {
    if (!isOAuth2Enabled) {
      throw new Error("OAuth2 is not enabled");
    }

    // 生成 state 参数防止 CSRF
    const state = Math.random().toString(36).substring(7);
    localStorage.setItem("oauth2_state", state);
    
    // 重定向到授权服务器
    const authUrl = oauth2Service.getAuthorizationUrl(state);
    window.location.href = authUrl;
  };

  // 手动刷新令牌
  const refreshToken = async (): Promise<boolean> => {
    if (!user?.refreshToken) return false;
    return refreshTokenSilently(user);
  };

  // 登出
  const logout = async () => {
    setIsLoading(true);
    
    try {
      // 如果是 OAuth2 用户，撤销令牌
      if (user?.accessToken) {
        await oauth2Service.revokeToken(user.accessToken);
      }
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      setUser(null);
      localStorage.removeItem("user");
      localStorage.removeItem("oauth2_state");
      setIsLoading(false);
    }
  };

  // 提供认证上下文
  const contextValue: AuthContextType = {
    user,
    isLoading,
    isAuthenticated: !!user,
    login,
    loginWithOAuth2,
    logout,
    refreshToken,
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

// 使用认证上下文的 Hook
export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
```

### 第五步：更新登录页面

修改现有的 `app/login/page.tsx` 文件，添加 OAuth2 登录支持：

```typescript
"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/contexts/auth-context";
import { Eye, EyeOff, Loader2 } from "lucide-react";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const { login, loginWithOAuth2, isAuthenticated } = useAuth();
  const router = useRouter();

  // 检查是否启用 OAuth2
  const isOAuth2Enabled = process.env.NEXT_PUBLIC_OAUTH_ENABLED === 'true';

  // 如果已经认证，重定向到首页
  useEffect(() => {
    if (isAuthenticated) {
      router.push("/");
    }
  }, [isAuthenticated, router]);

  // 处理传统用户名密码登录
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!username || !password) {
      setError("请输入用户名和密码");
      return;
    }
    
    setError(null);
    setIsLoggingIn(true);
    
    try {
      const success = await login(username, password);
      if (success) {
        router.push("/");
      } else {
        setError("用户名或密码错误");
      }
    } catch (err) {
      console.error("Login error:", err);
      setError("登录失败，请重试");
    } finally {
      setIsLoggingIn(false);
    }
  };

  // 处理 OAuth2 登录
  const handleOAuth2Login = async () => {
    setError(null);
    setIsLoggingIn(true);
    
    try {
      await loginWithOAuth2();
      // 重定向会在 loginWithOAuth2 中处理
    } catch (err) {
      console.error("OAuth2 login error:", err);
      setError("OAuth2 登录失败，请重试");
      setIsLoggingIn(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            登录到管理后台
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            {isOAuth2Enabled ? "使用统一认证服务登录" : "使用测试账号登录"}
          </p>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-md p-4">
            <div className="text-sm text-red-700">{error}</div>
          </div>
        )}

        {isOAuth2Enabled ? (
          // OAuth2 登录界面
          <div>
            <button
              onClick={handleOAuth2Login}
              disabled={isLoggingIn}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoggingIn && (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              )}
              {isLoggingIn ? "正在跳转..." : "统一认证登录"}
            </button>
            
            <div className="mt-4 text-center">
              <p className="text-sm text-gray-500">
                点击按钮将跳转到 WeSpringAuthServer 完成认证
              </p>
            </div>
          </div>
        ) : (
          // 传统用户名密码登录界面（保持原有设计）
          <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
            <div className="rounded-md shadow-sm -space-y-px">
              <div>
                <label htmlFor="username" className="sr-only">
                  用户名
                </label>
                <input
                  id="username"
                  name="username"
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="relative block w-full px-3 py-2 border border-gray-300 rounded-t-md placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                  placeholder="用户名"
                />
              </div>
              <div className="relative">
                <label htmlFor="password" className="sr-only">
                  密码
                </label>
                <input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="relative block w-full px-3 py-2 pr-10 border border-gray-300 rounded-b-md placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                  placeholder="密码"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                >
                  {showPassword ? (
                    <EyeOff className="h-5 w-5 text-gray-400" />
                  ) : (
                    <Eye className="h-5 w-5 text-gray-400" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isLoggingIn}
                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoggingIn && (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                )}
                {isLoggingIn ? "登录中..." : "登录"}
              </button>
            </div>

            <div className="text-center">
              <p className="text-sm text-gray-500">
                测试账号：admin/admin, distributor/distributor, store/store
              </p>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
```

### 第六步：创建 OAuth2 回调处理页面

创建 `app/auth/callback/page.tsx` 文件，处理 OAuth2 授权码回调：

```typescript
"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/contexts/auth-context";
import { oauth2Service } from "@/lib/oauth2-service";
import { Loader2 } from "lucide-react";

export default function OAuth2CallbackPage() {
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user, isAuthenticated } = useAuth();

  useEffect(() => {
    const handleCallback = async () => {
      try {
        // 获取 URL 参数
        const code = searchParams.get('code');
        const state = searchParams.get('state');
        const errorParam = searchParams.get('error');

        // 检查是否有错误
        if (errorParam) {
          throw new Error(`OAuth2 Error: ${errorParam}`);
        }

        // 检查必要参数
        if (!code) {
          throw new Error('Authorization code not found');
        }

        // 验证 state 参数（防止 CSRF）
        const storedState = localStorage.getItem('oauth2_state');
        if (state !== storedState) {
          throw new Error('Invalid state parameter');
        }

        setStatus('processing');

        // 交换授权码获取令牌
        console.log('Exchanging authorization code for tokens...');
        const tokenResponse = await oauth2Service.exchangeCodeForTokens(code);

        // 获取用户信息
        console.log('Fetching user info...');
        const userInfo = await oauth2Service.getUserInfo(tokenResponse.access_token);

        // 转换为应用用户对象
        const appUser = oauth2Service.mapOAuth2UserToAppUser(userInfo, tokenResponse.access_token);
        
        // 添加令牌信息
        const userWithTokens = {
          ...appUser,
          accessToken: tokenResponse.access_token,
          refreshToken: tokenResponse.refresh_token,
          tokenExpiresAt: Date.now() + tokenResponse.expires_in * 1000,
        };

        // 保存用户信息
        localStorage.setItem('user', JSON.stringify(userWithTokens));
        localStorage.removeItem('oauth2_state');

        setStatus('success');

        // 延迟重定向，让用户看到成功消息
        setTimeout(() => {
          router.push('/');
        }, 1500);

      } catch (error) {
        console.error('OAuth2 callback error:', error);
        setError(error instanceof Error ? error.message : 'Unknown error occurred');
        setStatus('error');
      }
    };

    // 如果用户已经认证，直接重定向
    if (isAuthenticated) {
      router.push('/');
      return;
    }

    handleCallback();
  }, [searchParams, router, isAuthenticated]);

  // 重试处理
  const handleRetry = () => {
    router.push('/login');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          {status === 'processing' && (
            <>
              <Loader2 className="mx-auto h-12 w-12 animate-spin text-indigo-600" />
              <h2 className="mt-6 text-xl font-semibold text-gray-900">
                正在处理认证...
              </h2>
              <p className="mt-2 text-sm text-gray-600">
                请稍候，我们正在验证您的身份信息
              </p>
            </>
          )}

          {status === 'success' && (
            <>
              <div className="mx-auto h-12 w-12 text-green-600">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h2 className="mt-6 text-xl font-semibold text-gray-900">
                认证成功！
              </h2>
              <p className="mt-2 text-sm text-gray-600">
                正在跳转到管理后台...
              </p>
            </>
          )}

          {status === 'error' && (
            <>
              <div className="mx-auto h-12 w-12 text-red-600">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <h2 className="mt-6 text-xl font-semibold text-gray-900">
                认证失败
              </h2>
              <p className="mt-2 text-sm text-gray-600">
                {error || '未知错误，请重试'}
              </p>
              <div className="mt-6">
                <button
                  onClick={handleRetry}
                  className="w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                >
                  返回登录
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
```

### 第七步：更新权限上下文

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

### 第七步：更新权限上下文

修改现有的 `contexts/permissions-context.tsx` 文件，使其支持 OAuth2 权限：

```typescript
import {
  createContext,
  useContext,
  ReactNode,
  useEffect,
  useState,
} from "react";
import { useAuth } from "./auth-context";
import { UserRole, Permission } from "@/types";

// 权限上下文类型（保持原有结构）
type PermissionsContextType = {
  permissions: Permission[];
  hasPermission: (resource: string, action: string) => boolean;
  hasPermissionForFields: (resource: string, action: string, fields: string[]) => boolean;
  getVisibleFields: (resource: string) => string[];
  // 新增：OAuth2 权限检查
  hasAuthority: (authority: string) => boolean;
  hasAnyAuthority: (...authorities: string[]) => boolean;
  isInGroup: (group: string) => boolean;
  isLoading: boolean;
};

// 创建权限上下文
const PermissionsContext = createContext<PermissionsContextType | undefined>(undefined);

// 权限提供者组件
export function PermissionsProvider({ children }: { children: ReactNode }) {
  const { user, isLoading: authLoading } = useAuth();
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const loadPermissions = async () => {
      setIsLoading(true);
      
      try {
        if (!user) {
          setPermissions([]);
          return;
        }

        let userPermissions: Permission[];

        // 检查是否为 OAuth2 用户
        const extendedUser = user as any;
        if (extendedUser.authorities && Array.isArray(extendedUser.authorities)) {
          // OAuth2 用户：从 authorities 映射权限
          userPermissions = mapAuthoritiesToPermissions(extendedUser.authorities);
        } else {
          // 传统用户：从角色获取权限
          userPermissions = getPermissionsByRole(user.role);
        }

        setPermissions(userPermissions);
      } catch (error) {
        console.error('Failed to load permissions:', error);
        setPermissions([]);
      } finally {
        setIsLoading(false);
      }
    };

    if (!authLoading) {
      loadPermissions();
    }
  }, [user, authLoading]);

  // 从 OAuth2 authorities 映射到权限
  const mapAuthoritiesToPermissions = (authorities: string[]): Permission[] => {
    const permissions: Permission[] = [];
    
    // 为每个 authority 创建对应的权限
    authorities.forEach(authority => {
      // 映射常见的权限模式
      if (authority.startsWith('Users_')) {
        const action = authority.replace('Users_', '').toLowerCase();
        permissions.push({ resource: 'users', action });
      } else if (authority.startsWith('Consultants_')) {
        const action = authority.replace('Consultants_', '').toLowerCase();
        permissions.push({ resource: 'consultants', action });
      } else if (authority.startsWith('Customers_')) {
        const action = authority.replace('Customers_', '').toLowerCase();
        permissions.push({ resource: 'customers', action });
      } else if (authority.startsWith('Stores_')) {
        const action = authority.replace('Stores_', '').toLowerCase();
        permissions.push({ resource: 'stores', action });
      } else if (authority.startsWith('Distributors_')) {
        const action = authority.replace('Distributors_', '').toLowerCase();
        permissions.push({ resource: 'distributors', action });
      }
      // 角色权限
      else if (authority === 'ROLE_ADMIN' || authority === 'ROLE_HEADQUARTERS_ADMIN') {
        // 管理员拥有所有权限
        permissions.push(...getAllPermissions());
      }
      // 可以根据需要添加更多映射规则
    });

    return permissions;
  };

  // 获取所有权限（管理员使用）
  const getAllPermissions = (): Permission[] => {
    return [
      // 用户管理
      { resource: "users", action: "read" },
      { resource: "users", action: "write" },
      { resource: "users", action: "delete" },
      // 咨询师管理
      { resource: "consultants", action: "read" },
      { resource: "consultants", action: "write" },
      { resource: "consultants", action: "approve" },
      // 顾客管理
      { resource: "customers", action: "read" },
      { resource: "customers", action: "write" },
      // 门店管理
      { resource: "stores", action: "read" },
      { resource: "stores", action: "write" },
      // 经销商管理
      { resource: "distributors", action: "read" },
      { resource: "distributors", action: "write" },
      // 更多权限...
    ];
  };

  // 原有的根据角色获取权限逻辑（保持兼容）
  const getPermissionsByRole = (role: UserRole): Permission[] => {
    // 保持原有的权限配置逻辑
    const basePermissions: Record<UserRole, Permission[]> = {
      headquarters_admin: getAllPermissions(),
      distributor_admin: [
        { resource: "customers", action: "read" },
        { resource: "customers", action: "write" },
        { resource: "consultants", action: "read" },
        { resource: "stores", action: "read" },
        // 更多经销商管理员权限...
      ],
      store_admin: [
        { resource: "customers", action: "read" },
        { resource: "customers", action: "write" },
        { resource: "consultants", action: "read" },
        // 更多门店管理员权限...
      ],
      // 其他角色权限...
      distributor_employee: [],
      consultant: [],
      customer: [],
    };

    return basePermissions[role] || [];
  };

  // 检查资源权限
  const hasPermission = (resource: string, action: string): boolean => {
    return permissions.some(p => p.resource === resource && p.action === action);
  };

  // 检查字段权限
  const hasPermissionForFields = (resource: string, action: string, fields: string[]): boolean => {
    const permission = permissions.find(p => p.resource === resource && p.action === action);
    if (!permission) return false;
    if (!permission.fields) return true; // 如果没有字段限制，则允许所有字段
    return fields.every(field => permission.fields!.includes(field));
  };

  // 获取可见字段
  const getVisibleFields = (resource: string): string[] => {
    const readPermission = permissions.find(p => p.resource === resource && p.action === "read");
    return readPermission?.fields || [];
  };

  // OAuth2 权限检查方法
  const hasAuthority = (authority: string): boolean => {
    const extendedUser = user as any;
    return extendedUser?.authorities?.includes(authority) || false;
  };

  const hasAnyAuthority = (...authorities: string[]): boolean => {
    return authorities.some(authority => hasAuthority(authority));
  };

  const isInGroup = (group: string): boolean => {
    const extendedUser = user as any;
    if (!extendedUser?.groups) return false;
    
    // 支持带或不带 GROUP_ 前缀的组名
    const groupsToCheck = [group, `GROUP_${group}`];
    return groupsToCheck.some(g => extendedUser.groups.includes(g));
  };

  const contextValue: PermissionsContextType = {
    permissions,
    hasPermission,
    hasPermissionForFields,
    getVisibleFields,
    hasAuthority,
    hasAnyAuthority,
    isInGroup,
    isLoading,
  };

  return (
    <PermissionsContext.Provider value={contextValue}>
      {children}
    </PermissionsContext.Provider>
  );
}

// 使用权限上下文的 Hook
export function usePermissions(): PermissionsContextType {
  const context = useContext(PermissionsContext);
  if (!context) {
    throw new Error('usePermissions must be used within a PermissionsProvider');
  }
  return context;
}
```

### 第八步：创建 API 调用工具

创建 `lib/api-client-with-auth.ts` 文件，为 API 调用自动添加认证头：

```typescript
// 扩展现有的 API 工具，添加认证支持
export class AuthenticatedApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000/api') {
    this.baseUrl = baseUrl;
  }

  // 获取认证头
  private getAuthHeaders(): HeadersInit {
    const user = this.getCurrentUser();
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };

    if (user?.accessToken) {
      headers['Authorization'] = `Bearer ${user.accessToken}`;
    }

    return headers;
  }

  // 从 localStorage 获取当前用户
  private getCurrentUser(): any {
    if (typeof window === 'undefined') return null;
    
    try {
      const userStr = localStorage.getItem('user');
      return userStr ? JSON.parse(userStr) : null;
    } catch {
      return null;
    }
  }

  // 通用请求方法
  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = this.getAuthHeaders();

    const response = await fetch(url, {
      ...options,
      headers: {
        ...headers,
        ...options.headers,
      },
    });

    if (!response.ok) {
      if (response.status === 401) {
        // 令牌过期，清除用户信息并重定向到登录页
        localStorage.removeItem('user');
        window.location.href = '/login';
        throw new Error('Authentication required');
      }
      throw new Error(`API request failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  // GET 请求
  async get<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET' });
  }

  // POST 请求
  async post<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  // PUT 请求
  async put<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  // DELETE 请求
  async delete<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }
}

export const authApiClient = new AuthenticatedApiClient();
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

### 第一步：配置 WeSpringAuthServer Client

在 WeSpringAuthServer 中注册您的应用为 OAuth2 Client：

```sql
-- 在 WeSpringAuthServer 数据库中执行
INSERT INTO oauth2_registered_client (
    id, client_id, client_name, client_secret,
    authorization_grant_types, redirect_uris, scopes
) VALUES (
    'admin-console-client-id',
    'admin-console-client',
    'Admin Console',
    '{bcrypt}$2a$10$password_hash_here',
    'authorization_code,refresh_token',
    'http://localhost:3000/auth/callback',
    'openid,profile,email,authorities,groups'
);
```

### 第二步：启动服务

```bash
# 1. 启动 WeSpringAuthServer
cd /path/to/WeSpringAuthServer
./start.sh

# 2. 启动前端应用
cd /path/to/RuiChuangQi-AI/src/admin-console
npm run dev
```

### 第三步：测试认证流程

#### 开发环境测试（模拟认证）
1. 设置 `NEXT_PUBLIC_OAUTH_ENABLED=false`
2. 访问 `http://localhost:3000`
3. 使用测试账号登录：`admin/password`

#### 生产环境测试（OAuth2 认证）
1. 设置 `NEXT_PUBLIC_OAUTH_ENABLED=true`
2. 访问 `http://localhost:3000`
3. 点击"统一认证登录"
4. 跳转到 WeSpringAuthServer 登录页
5. 完成认证后自动回跳应用

### 第四步：验证权限系统

在现有页面中验证权限是否正常工作：

```typescript
// 在任意页面组件中添加权限测试
import { usePermissions } from '@/contexts/permissions-context'

export default function TestPermissions() {
  const { hasAuthority, hasPermission, isInGroup } = usePermissions()
  
  return (
    <div className="p-4 space-y-2">
      <h3>权限测试</h3>
      
      {/* 测试 OAuth2 权限 */}
      <div>Users_Read: {hasAuthority('Users_Read') ? '✅' : '❌'}</div>
      <div>ROLE_ADMIN: {hasAuthority('ROLE_ADMIN') ? '✅' : '❌'}</div>
      
      {/* 测试传统权限 */}
      <div>用户读取: {hasPermission('users', 'read') ? '✅' : '❌'}</div>
      
      {/* 测试组权限 */}
      <div>管理员组: {isInGroup('ADMIN_GROUP') ? '✅' : '❌'}</div>
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

## ❓ 常见问题与故障排查

### Q: 环境变量配置问题
**问题**: OAuth2 登录按钮不显示或认证失败

**解决方案**:
1. 检查 `.env.local` 文件中的环境变量是否正确设置
2. 确认 `NEXT_PUBLIC_OAUTH_ENABLED=true`
3. 验证 WeSpringAuthServer 地址是否可访问

### Q: OAuth2 回调失败
**问题**: 认证成功但回调页面显示错误

**解决方案**:
1. 检查 WeSpringAuthServer 中注册的回调 URL 是否匹配
2. 确认 `OAUTH_CLIENT_ID` 和 `OAUTH_CLIENT_SECRET` 配置正确
3. 查看浏览器控制台和网络请求是否有错误

### Q: 权限映射不正确
**问题**: 用户登录成功但权限不生效

**解决方案**:
1. 检查 OAuth2 scope 是否包含 `authorities` 和 `groups`
2. 验证 `mapAuthoritiesToPermissions` 函数的映射规则
3. 确认 WeSpringAuthServer 返回的权限格式

### Q: 令牌过期处理
**问题**: 用户需要频繁重新登录

**解决方案**:
1. 检查令牌刷新逻辑是否正常工作
2. 确认 `refresh_token` 在 localStorage 中正确保存
3. 验证 WeSpringAuthServer 的令牌过期时间配置

### Q: 开发与生产环境切换
**问题**: 需要在模拟认证和 OAuth2 认证之间切换

**解决方案**:
1. 使用环境变量 `NEXT_PUBLIC_OAUTH_ENABLED` 控制
2. 开发环境设为 `false`，生产环境设为 `true`
3. 确保两种模式下的用户数据结构兼容

## 🚀 部署指南

### 生产环境配置清单

1. **环境变量设置**:
   ```bash
   NEXT_PUBLIC_OAUTH_ENABLED=true
   NEXT_PUBLIC_WESPRING_AUTH_URL=https://your-auth-server.com
   OAUTH_CLIENT_SECRET=your-production-secret
   ```

2. **WeSpringAuthServer 配置**:
   - 注册生产环境的回调 URL
   - 配置正确的 CORS 策略
   - 确保 HTTPS 证书有效

3. **安全检查**:
   - 客户端密钥不能暴露在前端代码中
   - 回调 URL 使用 HTTPS
   - 令牌刷新机制正常工作

## 💡 最佳实践

1. **渐进式迁移**: 先在开发环境测试，再逐步迁移到生产环境
2. **权限映射**: 建立清晰的 OAuth2 权限到应用权限的映射关系
3. **错误处理**: 实现完善的认证错误处理和用户提示
4. **性能优化**: 合理使用权限缓存，避免频繁权限检查
5. **安全考虑**: 定期更新客户端密钥，监控异常登录行为

## 📋 集成检查清单

- [ ] 环境变量配置完成
- [ ] OAuth2Service 创建完成
- [ ] AuthContext 更新完成
- [ ] 登录页面支持 OAuth2
- [ ] 回调页面创建完成
- [ ] 权限上下文更新完成
- [ ] API 客户端添加认证头
- [ ] 测试模拟认证功能正常
- [ ] 测试 OAuth2 认证流程正常
- [ ] 权限控制验证通过
- [ ] 令牌刷新机制工作正常

🎉 **恭喜！** 您已完成 OAuth2 Client 集成，现在可以享受统一认证带来的便利！