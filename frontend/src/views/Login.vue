<template>
  <div class="login-container">
    <div class="login-background">
      <div class="login-bg-shape shape-1"></div>
      <div class="login-bg-shape shape-2"></div>
      <div class="login-bg-shape shape-3"></div>
    </div>

    <NCard class="login-card" :bordered="false">
      <div class="login-header">
        <NIcon size="48" color="#18a058" class="login-logo">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
          </svg>
        </NIcon>
        <NH1 class="login-title">WAF Dashboard</NH1>
        <NP class="login-subtitle">Web Application Firewall Management Console</NP>
      </div>

      <NForm
        ref="formRef"
        :model="formData"
        :rules="formRules"
        size="large"
        @submit.prevent="handleLogin"
      >
        <NFormItem path="username" :show-label="false">
          <NInput
            v-model:value="formData.username"
            placeholder="Username"
            :input-props="{ autocomplete: 'username' }"
            @keyup.enter="handleLogin"
          >
            <template #prefix>
              <NIcon><PersonOutline /></NIcon>
            </template>
          </NInput>
        </NFormItem>

        <NFormItem path="password" :show-label="false">
          <NInput
            v-model:value="formData.password"
            type="password"
            show-password-on="click"
            placeholder="Password"
            :input-props="{ autocomplete: 'current-password' }"
            @keyup.enter="handleLogin"
          >
            <template #prefix>
              <NIcon><LockClosedOutline /></NIcon>
            </template>
          </NInput>
        </NFormItem>

        <NFormItem>
          <div class="login-options">
            <NCheckbox v-model:checked="formData.rememberMe">
              Remember me
            </NCheckbox>
          </div>
        </NFormItem>

        <NButton
          type="primary"
          block
          size="large"
          :loading="loading"
          attr-type="submit"
        >
          Sign In
        </NButton>
      </NForm>

      <div class="login-footer">
        <p class="login-hint">
          Default credentials: admin / Admin@2024Secure!
        </p>
      </div>
    </NCard>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import {
  NCard,
  NForm,
  NFormItem,
  NInput,
  NButton,
  NCheckbox,
  NIcon,
  NH1,
  NP,
  useMessage,
  type FormInst,
  type FormRules,
} from 'naive-ui'
import { PersonOutline, LockClosedOutline } from '@vicons/ionicons5'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const message = useMessage()

const formRef = ref<FormInst | null>(null)
const loading = ref(false)
const isInstalled = ref(true)

const formData = reactive({
  username: '',
  password: '',
  rememberMe: false,
})

const formRules: FormRules = {
  username: [
    { required: true, message: 'Please enter your username', trigger: 'blur' },
    { min: 3, max: 50, message: 'Username length should be 3-50 characters', trigger: 'blur' },
  ],
  password: [
    { required: true, message: 'Please enter your password', trigger: 'blur' },
    { min: 6, message: 'Password must be at least 6 characters', trigger: 'blur' },
  ],
}

onMounted(async () => {
  try {
    const response = await fetch('/api/v1/install/check', {
      method: 'GET',
    })
    const result = await response.json()
    if (!result.installed) {
      isInstalled.value = false
      router.replace('/install')
      return
    }
    formData.username = 'admin'
  } catch {
    isInstalled.value = true
    formData.username = 'admin'
  }
})

async function handleLogin() {
  try {
    await formRef.value?.validate()
  } catch {
    return
  }

  loading.value = true

  const result = await authStore.login(formData.username, formData.password)
  loading.value = false

  if (result.success) {
    message.success('Welcome back!')

    const redirect = (route.query.redirect as string) || '/dashboard'
    router.push(redirect)
  } else {
    message.error(result.error || 'Invalid username or password')
  }
}
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background-color: #f5f7fa;
  position: relative;
  overflow: hidden;
}

.login-background {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  overflow: hidden;
  z-index: 0;
}

.login-bg-shape {
  position: absolute;
  border-radius: 50%;
  opacity: 0.08;
}

.shape-1 {
  width: 600px;
  height: 600px;
  background: #18a058;
  top: -200px;
  right: -200px;
}

.shape-2 {
  width: 400px;
  height: 400px;
  background: #4098fc;
  bottom: -150px;
  left: -100px;
}

.shape-3 {
  width: 300px;
  height: 300px;
  background: #f0a020;
  top: 50%;
  left: 30%;
}

.login-card {
  width: 420px;
  border-radius: 16px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.15);
  z-index: 1;
  padding: 16px;
}

.login-header {
  text-align: center;
  margin-bottom: 32px;
}

.login-logo {
  margin-bottom: 16px;
}

.login-title {
  font-size: 28px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 8px;
}

.login-subtitle {
  font-size: 14px;
  color: var(--text-secondary);
}

.login-options {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.login-footer {
  margin-top: 24px;
  text-align: center;
}

.login-hint {
  font-size: 12px;
  color: var(--text-muted);
}
</style>
