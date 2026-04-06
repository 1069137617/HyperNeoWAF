import { createI18n } from 'vue-i18n'
import en from './locales/en-US.json'
import zhCN from './locales/zh-CN.json'

const i18n = createI18n({
  legacy: false,
  locale: localStorage.getItem('locale') || 'en-US',
  fallbackLocale: 'en-US',
  messages: {
    'en-US': en,
    'zh-CN': zhCN,
  },
})

export default i18n
