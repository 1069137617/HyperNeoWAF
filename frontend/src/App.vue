<template>
  <NConfigProvider :locale="naiveLocale" :theme="theme">
    <NMessageProvider>
      <NDialogProvider>
        <NNotificationProvider>
          <NLoadingBarProvider>
            <div class="app-layout">
              <router-view />
            </div>
          </NLoadingBarProvider>
        </NNotificationProvider>
      </NDialogProvider>
    </NMessageProvider>
  </NConfigProvider>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import {
  NConfigProvider,
  NMessageProvider,
  NDialogProvider,
  NNotificationProvider,
  NLoadingBarProvider,
  darkTheme
} from 'naive-ui'
import { useI18n } from 'vue-i18n'

const { locale } = useI18n()

const theme = computed(() => {
  // TODO: Implement theme switching based on user preference
  return null // null = light theme
})

const naiveLocale = computed(() => {
  // Map i18n locale to Naive UI locale
  const localeMap: Record<string, any> = {
    'en-US': null, // default English
    'zh-CN': () => import('naive-ui/es/locales/lang/zhCN')
  }
  return localeMap[locale.value] || null
})
</script>

<style scoped>
.app-layout {
  min-height: 100vh;
}
</style>
