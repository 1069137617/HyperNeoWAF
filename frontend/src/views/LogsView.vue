<template>
  <div class="logs-page">
    <NCard :bordered="false">
      <template #header>
        <NSpace align="center" justify="space-between" style="width: 100%;">
          <span>Log Audit Center</span>
          <NSpace>
            <NButton @click="exportLogs" :loading="exporting">
              <template #icon>
                <NIcon><DownloadOutline /></NIcon>
              </template>
              Export
            </NButton>
          </NSpace>
        </NSpace>
      </template>

      <!-- Filters -->
      <div class="filters-bar">
        <NGrid :cols="6" :x-gap="12" responsive="screen" item-responsive>
          <NGi span="0:24 8:6">
            <NDatePicker
              v-model:value="dateRange"
              type="datetimerange"
              clearable
              style="width: 100%;"
              @update:value="applyFilters"
            />
          </NGi>

          <NGi span="0:24 8:6">
            <NInput
              v-model:value="filters.clientIP"
              placeholder="Client IP"
              clearable
              @clear="applyFilters"
              @keyup.enter="applyFilters"
            />
          </NGi>

          <NGi span="0:24 8:4">
            <NSelect
              v-model:value="filters.method"
              :options="methodOptions"
              placeholder="Method"
              clearable
              @update:value="applyFilters"
            />
          </NGi>

          <NGi span="0:24 8:4">
            <NSelect
              v-model:value="filters.wafAction"
              :options="actionOptions"
              placeholder="WAF Action"
              clearable
              @update:value="applyFilters"
            />
          </NGi>

          <NGi span="0:24 8:4">
            <NInput
              v-model:value="filters.searchTerm"
              placeholder="Search..."
              clearable
              @keyup.enter="applyFilters"
              @clear="applyFilters"
            />
          </NGi>

          <NGi span="0:24 8:4">
            <NButton @click="resetFilters">Reset</NButton>
          </NGi>
        </NGrid>
      </div>

      <!-- Logs Table -->
      <NDataTable
        :columns="columns"
        :data="logs"
        :loading="loading"
        :pagination="pagination"
        :bordered="false"
        striped
        size="small"
        :row-key="(row: any) => row.id"
        @update:page="handlePageChange"
        @update:page-size="handlePageSizeChange"
      />
    </NCard>

    <!-- Log Detail Drawer -->
    <NDrawer
      v-model:show="showDrawer"
      :width="600"
      placement="right"
      :mask-closable="true"
    >
      <NDrawerContent title="Log Entry Details" closable>
        <template #default>
          <NDescriptions
            v-if="selectedLog"
            :column="1"
            label-placement="left"
            bordered
            size="small"
          >
            <NDescriptionsItem label="ID">{{ selectedLog.id }}</NDescriptionsItem>
            <NDescriptionsItem label="Timestamp">{{ formatTime(selectedLog.timestamp) }}</NDescriptionsItem>
            <NDescriptionsItem label="Client IP">
              <NText code>{{ selectedLog.clientIp }}</NText>
            </NDescriptionsItem>
            <NDescriptionsItem label="Method">
              <NTag :type="getMethodTagType(selectedLog.method)" size="small">
                {{ selectedLog.method }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="URI">{{ selectedLog.uri }}</NDescriptionsItem>
            <NDescriptionsItem label="Status Code">
              <NTag :type="getStatusTagType(selectedLog.statusCode)" size="small">
                {{ selectedLog.statusCode }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="WAF Action">
              <NTag :type="getActionTagType(selectedLog.wafAction)" size="small">
                {{ selectedLog.wafAction }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="WAF Rule">{{ selectedLog.wafRule || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="WAF Reason">{{ selectedLog.wafReason || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="Request Time">{{ selectedLog.requestTime?.toFixed(4) }}s</NDescriptionsItem>
            <NDescriptionsItem label="Bytes Sent">{{ formatBytes(selectedLog.bytesSent) }}</NDescriptionsItem>
          </NDescriptions>
        </template>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, h } from 'vue'
import {
  NCard,
  NSpace,
  NButton,
  NIcon,
  NGrid,
  NGi,
  NInput,
  NSelect,
  NDatePicker,
  NDataTable,
  NDrawer,
  NDrawerContent,
  NDescriptions,
  NDescriptionsItem,
  NTag,
  NText,
  useMessage,
  type DataTableColumns,
} from 'naive-ui'
import { DownloadOutline, SearchOutline, EyeOutline } from '@vicons/ionicons5'
import request from '@/api/request'

interface LogEntry {
  id: number
  timestamp: string
  clientIp: string
  method: string
  uri: string
  statusCode: number
  wafAction: string
  wafRule: string
  wafReason: string
  requestTime: number
  bytesSent: number
  bodyBytesSent: number
}

const message = useMessage()

const loading = ref(false)
const exporting = ref(false)
const logs = ref<LogEntry[]>([])
const showDrawer = ref(false)
const selectedLog = ref<LogEntry | null>(null)
const dateRange = ref<[number, number] | null>(null)

const filters = reactive({
  clientIP: '',
  method: null as string | null,
  wafAction: null as string | null,
  searchTerm: '',
})

const pagination = reactive({
  page: 1,
  pageSize: 20,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
})

const methodOptions = [
  { label: 'GET', value: 'GET' },
  { label: 'POST', value: 'POST' },
  { label: 'PUT', value: 'PUT' },
  { label: 'DELETE', value: 'DELETE' },
  { label: 'PATCH', value: 'PATCH' },
]

const actionOptions = [
  { label: 'Allow', value: 'allow' },
  { label: 'Deny', value: 'deny' },
  { label: 'Rate Limited', value: 'rate_limited' },
]

// Table columns
const columns: DataTableColumns<LogEntry> = [
  { title: 'ID', key: 'id', width: 70, sorter: 'default' },
  {
    title: 'Time',
    key: 'timestamp',
    width: 170,
    sorter: 'default',
    render: (row) => formatTime(row.timestamp),
  },
  {
    title: 'Client IP',
    key: 'clientIp',
    width: 140,
    render: (row) => h(NText, { code: true }, { default: () => row.clientIp }),
  },
  {
    title: 'Method',
    key: 'method',
    width: 80,
    render: (row) => h(NTag, {
      type: getMethodTagType(row.method),
      size: 'small',
      round: true,
      bordered: false,
    }, { default: () => row.method }),
  },
  {
    title: 'URI',
    key: 'uri',
    ellipsis: { tooltip: true },
    render: (row) => truncate(row.uri, 80),
  },
  {
    title: 'Status',
    key: 'statusCode',
    width: 75,
    render: (row) => h(NTag, {
      type: getStatusTagType(row.statusCode),
      size: 'small',
      round: true,
      bordered: false,
    }, { default: () => String(row.statusCode) }),
  },
  {
    title: 'WAF Action',
    key: 'wafAction',
    width: 110,
    render: (row) => h(NTag, {
      type: getActionTagType(row.wafAction),
      size: 'small',
      round: true,
      bordered: false,
    }, { default: () => row.wafAction?.replace('_', ' ') || '-' }),
  },
  {
    title: 'WAF Rule',
    key: 'wafRule',
    ellipsis: { tooltip: true },
    width: 150,
  },
  { title: 'Time', key: 'requestTime', width: 85, render: (row) => `${row.requestTime?.toFixed(2)}s` },
  {
    title: 'Actions',
    key: 'actions',
    width: 60,
    render: (row) => h(NButton, {
      size: 'tiny',
      quaternary: true,
      onClick: () => viewDetail(row),
    }, { default: () => h(NIcon, null, { default: () => h(EyeOutline) }) }),
  },
]

async function fetchLogs() {
  loading.value = true

  try {
    const params: Record<string, any> = {
      page: pagination.page,
      page_size: pagination.pageSize,
    }

    if (filters.clientIP) params.client_ip = filters.clientIP
    if (filters.method) params.method = filters.method
    if (filters.wafAction) params.waf_action = filters.wafAction
    if (filters.searchTerm) params.search = filters.searchTerm

    if (dateRange.value && dateRange.value[0] && dateRange.value[1]) {
      params.start_time = new Date(dateRange.value[0]).toISOString()
      params.end_time = new Date(dateRange.value[1]).toISOString()
    }

    const response = await request.get('/logs', { params })
    const data = response.data

    logs.value = data.data || []
    pagination.itemCount = data.total || 0
  } catch (error) {
    console.error('Failed to fetch logs:', error)
    message.error('Failed to load logs')
  } finally {
    loading.value = false
  }
}

function handlePageChange(page: number) {
  pagination.page = page
  fetchLogs()
}

function handlePageSizeChange(pageSize: number) {
  pagination.pageSize = pageSize
  pagination.page = 1
  fetchLogs()
}

function applyFilters() {
  pagination.page = 1
  fetchLogs()
}

function resetFilters() {
  filters.clientIP = ''
  filters.method = null
  filters.wafAction = null
  filters.searchTerm = ''
  dateRange.value = null
  applyFilters()
}

function viewDetail(log: LogEntry) {
  selectedLog.value = log
  showDrawer.value = true
}

async function exportLogs() {
  exporting.value = true

  try {
    const params: Record<string, any> = { format: 'json' }

    if (dateRange.value && dateRange.value[0] && dateRange.value[1]) {
      params.start_time = new Date(dateRange.value[0]).toISOString()
      params.end_time = new Date(dateRange.value[1]).toISOString()
    }

    const response = await request.get('/logs/export', {
      params,
      responseType: 'blob',
    })

    // Create download link
    const url = window.URL.createObjectURL(new Blob([response.data]))
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', `waf-logs-${new Date().toISOString().slice(0, 10)}.json`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)

    message.success('Logs exported successfully')
  } catch (error) {
    message.error('Failed to export logs')
  } finally {
    exporting.value = false
  }
}

// Format helpers
function formatTime(timestamp: string): string {
  return new Date(timestamp).toLocaleString()
}

function truncate(str: string, len: number): string {
  return str.length > len ? str.substring(0, len) + '...' : str
}

function formatBytes(bytes: number): string {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function getMethodTagType(method: string): 'info' | 'success' | 'warning' | 'error' | 'default' {
  const map: Record<string, any> = {
    GET: 'success',
    POST: 'info',
    PUT: 'warning',
    DELETE: 'error',
    PATCH: 'warning',
  }
  return map[method] || 'default'
}

function getStatusTagType(code: number): 'success' | 'warning' | 'error' | 'default' {
  if (code >= 200 && code < 300) return 'success'
  if (code >= 300 && code < 400) return 'warning'
  if (code >= 400) return 'error'
  return 'default'
}

function getActionTagType(action: string): 'success' | 'error' | 'warning' | 'default' {
  const map: Record<string, any> = {
    allow: 'success',
    deny: 'error',
    rate_limited: 'warning',
  }
  return map[action] || 'default'
}

onMounted(() => {
  fetchLogs()
})
</script>

<style scoped>
.logs-page {
  max-width: 1400px;
}

.filters-bar {
  margin-bottom: 16px;
  padding: 16px;
  background-color: var(--bg-secondary);
  border-radius: 8px;
}
</style>
