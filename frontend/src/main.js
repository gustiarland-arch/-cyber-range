import './services/captureToken' // first: strips #cr-token before the router reads the URL
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import i18n from './services/i18n'
import './style.css'

createApp(App).use(createPinia()).use(router).use(i18n).mount('#app')
