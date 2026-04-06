import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import request from '@/api/request'

interface UserInfo {
  id: number
  username: string
  role: string
}

interface LoginResponse {
  user: UserInfo
  access_token: string
  refresh_token: string
  expires_in: number
  token_type: string
}

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string | null>(localStorage.getItem('access_token'))
  const refreshToken = ref<string | null>(localStorage.getItem('refresh_token'))
  const user = ref<UserInfo | null>(null)

  const isAuthenticated = computed(() => !!token.value)

  async function login(username: string, password: string) {
    try {
      const response = await request.post<LoginResponse>('/auth/login', {
        username,
        password,
      })

      const data = response.data

      token.value = data.access_token
      refreshToken.value = data.refresh_token
      user.value = data.user

      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('refresh_token', data.refresh_token)

      return { success: true }
    } catch (error: any) {
      const message = error.response?.data?.message || 'Login failed'
      return { success: false, error: message }
    }
  }

  async function fetchProfile() {
    if (!token.value) return false

    try {
      const response = await request.get('/auth/profile')
      user.value = response.data.user
      return true
    } catch {
      return false
    }
  }

  async function refreshAccessToken() {
    if (!refreshToken.value) return false

    try {
      const response = await request.post<LoginResponse>('/auth/refresh', {
        refresh_token: refreshToken.value,
      })

      const data = response.data
      token.value = data.access_token
      refreshToken.value = data.refresh_token

      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('refresh_token', data.refresh_token)

      return true
    } catch {
      logout()
      return false
    }
  }

  function logout() {
    token.value = null
    refreshToken.value = null
    user.value = null

    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
  }

  function checkAuth() {
    if (!token.value) {
      logout()
      return false
    }

    // Optionally validate token by fetching profile
    return true
  }

  return {
    token,
    user,
    isAuthenticated,
    login,
    fetchProfile,
    refreshAccessToken,
    logout,
    checkAuth,
  }
})
