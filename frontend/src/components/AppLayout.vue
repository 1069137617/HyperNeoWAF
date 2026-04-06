<template>
  <NLayout has-sider class="app-layout">
    <!-- Sidebar -->
    <NLayoutSider
      bordered
      collapse-mode="width"
      :collapsed-width="64"
      :width="240"
      show-trigger
      :native-scrollbar="false"
      class="app-sider"
    >
      <div class="logo">
        <NIcon size="28" color="#18a058">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
          </svg>
        </NIcon>
        <span v-if="!collapsed" class="logo-text">WAF Dashboard</span>
      </div>

      <NMenu
        :value="activeKey"
        :options="menuOptions"
        :collapsed="collapsed"
        :collapsed-width="64"
        :collapsed-icon-size="22"
        @update:value="handleMenuUpdate"
      />
    </NLayoutSider>

    <!-- Main Content -->
    <NLayout>
      <!-- Header -->
      <NLayoutHeader bordered class="app-header">
        <div class="header-left">
          <NBreadcrumb>
            <NBreadcrumbItem>{{ currentRouteName }}</NBreadcrumbItem>
          </NBreadcrumb>
        </div>

        <div class="header-right">
          <!-- Language Switcher -->
          <NDropdown :options="languageOptions" @select="handleLanguageChange">
            <NButton quaternary>
              <template #icon>
                <NIcon><LanguageOutline /></NIcon>
              </template>
              {{ currentLanguage }}
            </NButton>
          </NDropdown>

          <!-- User Menu -->
          <NDropdown :options="userMenuOptions" @select="handleUserMenuSelect">
            <NAvatar round size="small" class="user-avatar">
              {{ userInitial }}
            </NAvatar>
          </NDropdown>
        </div>
      </NLayoutHeader>

      <!-- Content -->
      <NLayoutContent content-style="padding: 24px;" :native-scrollbar="false">
        <router-view />
      </NLayoutContent>
    </NLayout>
  </NLayout>
</template>

<script setup lang="ts">
import { computed, h, ref } from 'vue'
import { useRouter, useRoute, RouteRecordRaw } from 'vue-router'
import {
  NIcon,
  NLayout,
  NLayoutSider,
  NLayoutHeader,
  NLayoutContent,
  NMenu,
  NBreadcrumb,
  NBreadcrumbItem,
  NButton,
  NAvatar,
  NDropdown,
} from 'naive-ui'
import {
  DashboardOutline,
  ShieldCheckmarkOutline,
  DocumentTextOutline,
  PeopleOutline,
  SettingsOutline,
  LogOutOutline,
  PersonOutline,
  LanguageOutline,
} from '@vicons/ionicons5'
import { useAuthStore } from '@/stores/auth'
import { useI18n } from 'vue-i18n'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const { locale } = useI18n()

const collapsed = ref(false)
const activeKey = computed(() => route.name as string)

const currentRouteName = computed(() => {
  return route.meta?.title || 'WAF Dashboard'
})

const userInitial = computed(() => {
  return authStore.user?.username?.charAt(0)?.toUpperCase() || 'A'
})

// Menu options with SVG icons
const menuOptions = computed(() => [
  {
    label: () => t('nav.dashboard'),
    key: 'Dashboard',
    icon: () => h(NIcon, null, { default: () => h(DashboardOutline) }),
  },
  {
    label: () => t('nav.rules'),
    key: 'Rules',
    icon: () => h(NIcon, null, { default: () => h(ShieldCheckmarkOutline) }),
  },
  {
    label: () => t('nav.logs'),
    key: 'Logs',
    icon: () => h(NIcon, null, { default: () => h(DocumentTextOutline) }),
  },
  {
    label: () => t('nav.ipList'),
    key: 'IPList',
    icon: () => h(NIcon, null, { default: () => h(PeopleOutline) }),
  },
])

function handleMenuUpdate(key: string) {
  router.push({ name: key })
}

// Language options
const languageOptions = [
  { label: 'English', key: 'en-US' },
  { label: '中文', key: 'zh-CN' },
]

const currentLanguage = computed(() => {
  return locale.value === 'zh-CN' ? 'CN' : 'EN'
})

function handleLanguageChange(key: string) {
  locale.value = key
  localStorage.setItem('locale', key)
}

// User menu options
const userMenuOptions = [
  {
    label: () => t('common.profile') || 'Profile',
    key: 'profile',
    icon: () => h(NIcon, null, { default: () => h(PersonOutline) }),
  },
  { type: 'divider' as const },
  {
    label: () => t('nav.logout'),
    key: 'logout',
    icon: () => h(NIcon, null, { default: () => h(LogOutOutline) }),
  },
]

function handleUserMenuSelect(key: string) {
  if (key === 'logout') {
    authStore.logout()
    router.push('/login')
  }
}

// i18n helper
function t(key: string): string {
  // Simple translation lookup
  return key
}
</script>

<style scoped>
.app-layout {
  height: 100vh;
}

.app-sider {
  box-shadow: 2px 0 6px rgba(0, 0, 0, 0.05);
}

.logo {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 64px;
  padding: 16px;
  gap: 12px;
  border-bottom: 1px solid var(--border-color);
}

.logo-text {
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
  white-space: nowrap;
}

.app-header {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  background-color: var(--bg-primary);
}

.header-left {
  display: flex;
  align-items: center;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.user-avatar {
  cursor: pointer;
  background-color: #18a058;
  color: white;
}
</style>
