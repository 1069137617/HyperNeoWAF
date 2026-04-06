<template>
  <div class="install-container">
    <div class="install-background">
      <div class="install-bg-shape shape-1"></div>
      <div class="install-bg-shape shape-2"></div>
      <div class="install-bg-shape shape-3"></div>
    </div>

    <NCard class="install-card" :bordered="false">
      <div class="install-header">
        <NIcon size="48" color="#18a058" class="install-logo">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
          </svg>
        </NIcon>
        <NH1 class="install-title">{{ t('install.title') }}</NH1>
        <NP class="install-subtitle">{{ t('install.subtitle') }}</NP>
      </div>

      <NSteps :current="currentStep" size="small" class="install-steps">
        <NStep :title="t('install.step1Title')" :description="t('install.step1Desc')" />
        <NStep :title="t('install.step2Title')" :description="t('install.step2Desc')" />
        <NStep :title="t('install.step3Title')" :description="t('install.step3Desc')" />
      </NSteps>

      <NForm
        v-if="currentStep === 1"
        ref="formRef"
        :model="formData"
        :rules="formRules"
        size="large"
        @submit.prevent="handleCheckDeps"
      >
        <NDivider>{{ t('install.databaseConfig') }}</NDivider>

        <NGrid :cols="2" :x-gap="16">
          <NGi>
            <NFormItem path="db_host" :label="t('install.dbHost')">
              <NInput v-model:value="formData.db_host" placeholder="localhost">
                <template #prefix>
                  <NIcon><ServerOutline /></NIcon>
                </template>
              </NInput>
            </NFormItem>
          </NGi>
          <NGi>
            <NFormItem path="db_port" :label="t('install.dbPort')">
              <NInputNumber v-model:value="formData.db_port" :min="1" :max="65535" placeholder="5432" style="width: 100%">
              </NInputNumber>
            </NFormItem>
          </NGi>
          <NGi>
            <NFormItem path="db_user" :label="t('install.dbUser')">
              <NInput v-model:value="formData.db_user" placeholder="waf_admin">
                <template #prefix>
                  <NIcon><PersonOutline /></NIcon>
                </template>
              </NInput>
            </NFormItem>
          </NGi>
          <NGi>
            <NFormItem path="db_password" :label="t('install.dbPassword')">
              <NInput
                v-model:value="formData.db_password"
                type="password"
                show-password-on="click"
                placeholder="********"
              >
                <template #prefix>
                  <NIcon><LockClosedOutline /></NIcon>
                </template>
              </NInput>
            </NFormItem>
          </NGi>
          <NGi span="2">
            <NFormItem path="db_name" :label="t('install.dbName')">
              <NInput v-model:value="formData.db_name" placeholder="waf_db">
              </NInput>
            </NFormItem>
          </NGi>
        </NGrid>

        <NDivider>{{ t('install.redisConfig') }}</NDivider>

        <NGrid :cols="2" :x-gap="16">
          <NGi>
            <NFormItem path="redis_host" :label="t('install.redisHost')">
              <NInput v-model:value="formData.redis_host" placeholder="localhost">
                <template #prefix>
                  <NIcon><ServerOutline /></NIcon>
                </template>
              </NInput>
            </NFormItem>
          </NGi>
          <NGi>
            <NFormItem path="redis_port" :label="t('install.redisPort')">
              <NInputNumber v-model:value="formData.redis_port" :min="1" :max="65535" placeholder="6379" style="width: 100%">
              </NInputNumber>
            </NFormItem>
          </NGi>
          <NGi span="2">
            <NFormItem path="redis_password" :label="t('install.redisPassword')">
              <NInput
                v-model:value="formData.redis_password"
                type="password"
                show-password-on="click"
                placeholder=""
              >
                <template #prefix>
                  <NIcon><LockClosedOutline /></NIcon>
                </template>
              </NInput>
            </NFormItem>
          </NGi>
        </NGrid>

        <NSpace justify="end" style="margin-top: 24px">
          <NButton
            type="primary"
            size="large"
            :loading="checkingDeps"
            attr-type="submit"
          >
            {{ t('install.checkDeps') }}
          </NButton>
        </NSpace>
      </NForm>

      <div v-if="currentStep === 2" class="dep-check-result">
        <NSpin :show="checkingDeps">
          <div class="dep-status-list">
            <div class="dep-status-item" :class="depStatusClass('database')">
              <NIcon v-if="depResults.database?.status === 'ok'" size="24" color="#18a058">
                <CheckmarkCircle />
              </NIcon>
              <NIcon v-else-if="depResults.database?.status === 'failed'" size="24" color="#d03050">
                <CloseCircle />
              </NIcon>
              <NIcon v-else size="24" color="#909399">
                <EllipsisCircle />
              </NIcon>
              <span class="dep-status-label">{{ t('install.database') }}</span>
              <span class="dep-status-message">{{ depResults.database?.message || t('install.checking') }}</span>
            </div>

            <div class="dep-status-item" :class="depStatusClass('redis')">
              <NIcon v-if="depResults.redis?.status === 'ok'" size="24" color="#18a058">
                <CheckmarkCircle />
              </NIcon>
              <NIcon v-else-if="depResults.redis?.status === 'failed'" size="24" color="#d03050">
                <CloseCircle />
              </NIcon>
              <NIcon v-else size="24" color="#909399">
                <EllipsisCircle />
              </NIcon>
              <span class="dep-status-label">{{ t('install.redis') }}</span>
              <span class="dep-status-message">{{ depResults.redis?.message || t('install.checking') }}</span>
            </div>
          </div>
        </NSpin>

        <NSpace justify="end" style="margin-top: 24px" v-if="!checkingDeps">
          <NButton @click="currentStep = 1">{{ t('common.back') }}</NButton>
          <NButton
            v-if="canProceed"
            type="primary"
            @click="currentStep = 3"
          >
            {{ t('install.next') }}
          </NButton>
          <NButton
            v-else
            type="warning"
            @click="handleRetryCheck"
          >
            {{ t('install.retry') }}
          </NButton>
        </NSpace>
      </div>

      <NForm
        v-if="currentStep === 3"
        ref="adminFormRef"
        :model="adminFormData"
        :rules="adminFormRules"
        size="large"
      >
        <NDivider>{{ t('install.adminAccount') }}</NDivider>

        <NFormItem path="admin_username" :label="t('install.adminUsername')">
          <NInput v-model:value="adminFormData.admin_username" placeholder="admin">
            <template #prefix>
              <NIcon><PersonOutline /></NIcon>
            </template>
          </NInput>
        </NFormItem>

        <NFormItem path="admin_password" :label="t('install.adminPassword')">
          <NInput
            v-model:value="adminFormData.admin_password"
            type="password"
            show-password-on="click"
            placeholder="********"
          >
            <template #prefix>
              <NIcon><LockClosedOutline /></NIcon>
            </template>
          </NInput>
        </NFormItem>

        <NFormItem path="admin_password_confirm" :label="t('install.adminPasswordConfirm')">
          <NInput
            v-model:value="adminFormData.admin_password_confirm"
            type="password"
            show-password-on="click"
            placeholder="********"
          >
            <template #prefix>
              <NIcon><LockClosedOutline /></NIcon>
            </template>
          </NInput>
        </NFormItem>

        <NSpace justify="end" style="margin-top: 24px">
          <NButton @click="currentStep = 2">{{ t('common.back') }}</NButton>
          <NButton
            type="primary"
            size="large"
            :loading="installing"
            @click="handleInstall"
          >
            {{ t('install.startInstall') }}
          </NButton>
        </NSpace>
      </NForm>

      <div v-if="installSuccess" class="install-success">
        <NIcon size="64" color="#18a058">
          <CheckmarkCircle />
        </NIcon>
        <NH2>{{ t('install.successTitle') }}</NH2>
        <NP>{{ t('install.successMessage') }}</NP>
        <NButton type="primary" size="large" @click="goToLogin" style="margin-top: 24px">
          {{ t('install.goToLogin') }}
        </NButton>
      </div>
    </NCard>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import {
  NCard,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NButton,
  NIcon,
  NH1,
  NH2,
  NP,
  NSteps,
  NStep,
  NDivider,
  NGrid,
  NGi,
  NSpace,
  NSpin,
  useMessage,
  type FormInst,
  type FormRules,
} from 'naive-ui'
import {
  PersonOutline,
  LockClosedOutline,
  ServerOutline,
  CheckmarkCircle,
  CloseCircle,
  EllipsisCircle,
} from '@vicons/ionicons5'

const router = useRouter()
const message = useMessage()
const { t } = useI18n()

const currentStep = ref(1)
const checkingDeps = ref(false)
const installing = ref(false)
const installSuccess = ref(false)

const formRef = ref<FormInst | null>(null)
const adminFormRef = ref<FormInst | null>(null)

const formData = reactive({
  db_host: 'localhost',
  db_port: 5432,
  db_user: 'waf_admin',
  db_password: '',
  db_name: 'waf_db',
  redis_host: 'localhost',
  redis_port: 6379,
  redis_password: '',
})

const adminFormData = reactive({
  admin_username: 'admin',
  admin_password: '',
  admin_password_confirm: '',
})

const depResults = reactive({
  database: null as { status: string; message: string } | null,
  redis: null as { status: string; message: string } | null,
})

const formRules: FormRules = {
  db_host: [{ required: true, message: 'Please enter database host', trigger: 'blur' }],
  db_port: [{ required: true, message: 'Please enter database port', trigger: 'blur' }],
  db_user: [{ required: true, message: 'Please enter database user', trigger: 'blur' }],
  db_password: [{ required: true, message: 'Please enter database password', trigger: 'blur' }],
  db_name: [{ required: true, message: 'Please enter database name', trigger: 'blur' }],
  redis_host: [{ required: true, message: 'Please enter Redis host', trigger: 'blur' }],
  redis_port: [{ required: true, message: 'Please enter Redis port', trigger: 'blur' }],
}

const validatePasswordConfirm = (_rule: any, value: string, callback: any) => {
  if (value !== adminFormData.admin_password) {
    callback(new Error('Passwords do not match'))
  } else {
    callback()
  }
}

const adminFormRules: FormRules = {
  admin_username: [
    { required: true, message: 'Please enter username', trigger: 'blur' },
    { min: 3, max: 50, message: 'Username should be 3-50 characters', trigger: 'blur' },
  ],
  admin_password: [
    { required: true, message: 'Please enter password', trigger: 'blur' },
    { min: 8, max: 128, message: 'Password should be 8-128 characters', trigger: 'blur' },
  ],
  admin_password_confirm: [
    { required: true, message: 'Please confirm password', trigger: 'blur' },
    { validator: validatePasswordConfirm, trigger: 'blur' },
  ],
}

const canProceed = computed(() => {
  return depResults.database?.status === 'ok' && depResults.redis?.status === 'ok'
})

const depStatusClass = (type: 'database' | 'redis') => {
  const status = depResults[type]?.status
  if (status === 'ok') return 'status-ok'
  if (status === 'failed') return 'status-failed'
  return 'status-pending'
}

async function handleCheckDeps() {
  try {
    await formRef.value?.validate()
  } catch {
    return
  }

  checkingDeps.value = true
  depResults.database = { status: 'checking', message: t('install.checking') }
  depResults.redis = { status: 'checking', message: t('install.checking') }

  try {
    const response = await fetch('/api/v1/install/check-deps', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        db_host: formData.db_host,
        db_port: formData.db_port,
        db_user: formData.db_user,
        db_password: formData.db_password,
        db_name: formData.db_name,
        redis_host: formData.redis_host,
        redis_port: formData.redis_port,
        redis_password: formData.redis_password,
      }),
    })

    const result = await response.json()
    depResults.database = result.database
    depResults.redis = result.redis

    if (result.success) {
      currentStep.value = 2
    }
  } catch (error) {
    message.error('Connection check failed')
    depResults.database = { status: 'failed', message: 'Connection failed' }
    depResults.redis = { status: 'failed', message: 'Connection failed' }
  } finally {
    checkingDeps.value = false
  }
}

function handleRetryCheck() {
  handleCheckDeps()
}

async function handleInstall() {
  try {
    await adminFormRef.value?.validate()
  } catch {
    return
  }

  installing.value = true

  try {
    const response = await fetch('/api/v1/install/do', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        db_host: formData.db_host,
        db_port: formData.db_port,
        db_user: formData.db_user,
        db_password: formData.db_password,
        db_name: formData.db_name,
        redis_host: formData.redis_host,
        redis_port: formData.redis_port,
        redis_password: formData.redis_password,
        admin_username: adminFormData.admin_username,
        admin_password: adminFormData.admin_password,
      }),
    })

    const result = await response.json()

    if (result.success) {
      installSuccess.value = true
    } else {
      message.error(result.message || 'Installation failed')
    }
  } catch (error) {
    message.error('Installation failed')
  } finally {
    installing.value = false
  }
}

function goToLogin() {
  router.push('/login')
}
</script>

<style scoped>
.install-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background-color: #f5f7fa;
  position: relative;
  overflow: hidden;
}

.install-background {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  overflow: hidden;
  z-index: 0;
}

.install-bg-shape {
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

.install-card {
  width: 600px;
  border-radius: 16px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.15);
  z-index: 1;
  padding: 24px;
}

.install-header {
  text-align: center;
  margin-bottom: 24px;
}

.install-logo {
  margin-bottom: 16px;
}

.install-title {
  font-size: 28px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 8px;
}

.install-subtitle {
  font-size: 14px;
  color: var(--text-secondary);
}

.install-steps {
  margin-bottom: 24px;
}

.dep-check-result {
  padding: 16px 0;
}

.dep-status-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.dep-status-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  border-radius: 8px;
  background: #f5f7fa;
}

.dep-status-label {
  font-weight: 600;
  min-width: 100px;
}

.dep-status-message {
  color: var(--text-secondary);
}

.status-ok {
  background: #f0f9f4;
}

.status-failed {
  background: #fff1f0;
}

.status-pending {
  background: #f5f7fa;
}

.install-success {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 32px 0;
  text-align: center;
}

.install-success h2 {
  margin-top: 16px;
  margin-bottom: 8px;
}

.install-success p {
  color: var(--text-secondary);
}
</style>