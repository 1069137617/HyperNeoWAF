<template>
  <div class="ip-list-page">
    <NCard :bordered="false">
      <template #header>
        <NSpace align="center" justify="space-between" style="width: 100%;">
          <span>IP List Management</span>
          <NSpace>
            <NButton type="primary" @click="showAddModal">
              <template #icon>
                <NIcon><AddOutline /></NIcon>
              </template>
              Add IP
            </NButton>

            <NButton @click="showBatchImportModal">
              <template #icon>
                <NIcon><UploadOutline /></NIcon>
              </template>
              Batch Import
            </NButton>

            <NButton @click="syncToRedis" :loading="syncing">
              <template #icon>
                <NIcon><SyncOutline /></NIcon>
              </template>
              Sync to Redis
            </NButton>
          </NSpace>
        </NSpace>
      </template>

      <!-- Tabs for Blacklist/Whitelist -->
      <NTabs
        v-model:value="activeTab"
        type="line"
        animated
        @update:value="handleTabChange"
      >
        <NTabPane name="blacklist" tab="Blacklist">
          <div class="tab-content">
            <NDataTable
              :columns="blacklistColumns"
              :data="blacklistData"
              :loading="loading"
              :pagination="blacklistPagination"
              :bordered="false"
              striped
              size="small"
              @update:page="(p: number) => handleBlacklistPageChange(p)"
            />
          </div>
        </NTabPane>

        <NTabPane name="whitelist" tab="Whitelist">
          <div class="tab-content">
            <NDataTable
              :columns="whitelistColumns"
              :data="whitelistData"
              :loading="loading"
              :pagination="whitelistPagination"
              :bordered="false"
              striped
              size="small"
              @update:page="(p: number) => handleWhitelistPageChange(p)"
            />
          </div>
        </NTabPane>
      </NTabs>
    </NCard>

    <!-- Add/Edit Modal -->
    <NModal
      v-model:show="addModal"
      :title="'Add IP Entry'"
      preset="card"
      style="width: 500px;"
      :mask-closable="false"
    >
      <NForm
        ref="ipFormRef"
        :model="ipFormData"
        :rules="ipFormRules"
        label-placement="left"
        label-width="auto"
      >
        <NFormItem label="List Type" path="type">
          <NRadioGroup v-model:value="ipFormData.type">
            <NRadio value="blacklist">
              <template #default>
                <NIcon color="#d03050"><CloseCircleOutline /></NIcon>
                Blacklist
              </template>
            </NRadio>
            <NRadio value="whitelist">
              <template #default>
                <NIcon color="#18a058"><CheckmarkCircleOutline /></NIcon>
                Whitelist
              </template>
            </NRadio>
          </NRadioGroup>
        </NFormItem>

        <NFormItem label="IP Address" path="ip">
          <NInput
            v-model:value="ipFormData.ip"
            placeholder="e.g. 192.168.1.1 or 10.0.0.0/24"
          />
        </NFormItem>

        <NFormItem label="Reason" path="reason">
          <NInput
            v-model:value="ipFormData.reason"
            type="textarea"
            placeholder="Reason for adding this IP"
            :rows="2"
          />
        </NFormItem>

        <NFormItem label="Expires At" path="expiresAt">
          <NPicker
            v-model:formatted-value="ipFormData.expiresAt"
            type="datetime"
            clearable
            style="width: 100%;"
          />
        </NFormItem>
      </NForm>

      <template #footer>
        <NSpace justify="end">
          <NButton @click="addModal = false">Cancel</NButton>
          <NButton type="primary" :loading="submitting" @click="handleSubmitIP">Add</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Batch Import Modal -->
    <NModal
      v-model:show="batchImportModal"
      title="Batch Import IPs"
      preset="card"
      style="width: 500px;"
    >
      <NForm label-placement="top">
        <NFormItem label="List Type">
          <NRadioGroup v-model:value="batchImportType">
            <NRadio value="blacklist">Blacklist</NRadio>
            <NRadio value="whitelist">Whitelist</NRadio>
          </NRadioGroup>
        </NFormItem>

        <NFormItem label="IP Addresses (one per line)">
          <NInput
            v-model:value="batchImportText"
            type="textarea"
            placeholder="192.168.1.1&#10;10.0.0.0/24&#10;172.16.0.0/16"
            :rows="10"
          />
        </NFormItem>
      </NForm>

      <template #footer>
        <NSpace justify="end">
          <NButton @click="batchImportModal = false">Cancel</NButton>
          <NButton type="primary" :loading="importing" @click="handleBatchImport">Import</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, h } from 'vue'
import {
  NCard,
  NSpace,
  NButton,
  NIcon,
  NTabs,
  NTabPane,
  NDataTable,
  NModal,
  NForm,
  NFormItem,
  NInput,
  NRadioGroup,
  NRadio,
  NPicker,
  NPopconfirm,
  NTag,
  NText,
  useMessage,
  type FormInst,
  type DataTableColumns,
} from 'naive-ui'
import {
  AddOutline,
  UploadOutline,
  SyncOutline,
  CloseCircleOutline,
  CheckmarkCircleOutline,
  TrashOutline,
} from '@vicons/ionicons5'
import request from '@/api/request'

interface IPEntry {
  id: number
  ip: string
  type: string
  reason: string
  expiresAt: string | null
  source: string
  isActive: boolean
  createdAt: string
}

const message = useMessage()

const activeTab = ref('blacklist')
const loading = ref(false)
const syncing = ref(false)
const addModal = ref(false)
const batchImportModal = ref(false)
const submitting = ref(false)
const importing = ref(false)

const blacklistData = ref<IPEntry[]>([])
const whitelistData = ref<IPEntry[]>([])

const blacklistPagination = reactive({ page: 1, pageSize: 20, itemCount: 0, showSizePicker: true })
const whitelistPagination = reactive({ page: 1, pageSize: 20, itemCount: 0, showSizePicker: true })

const ipFormRef = ref<FormInst | null>(null)
const batchImportType = ref('blacklist')
const batchImportText = ref('')

const ipFormData = reactive({
  type: 'blacklist',
  ip: '',
  reason: '',
  expiresAt: null as number[] | null,
})

const ipFormRules = {
  type: { required: true, message: 'Please select list type', trigger: 'change' },
  ip: { required: true, message: 'IP address is required', trigger: 'blur' },
}

// Blacklist columns
const blacklistColumns: DataTableColumns<IPEntry> = [
  { title: 'ID', key: 'id', width: 60 },
  {
    title: 'IP Address',
    key: 'ip',
    ellipsis: { tooltip: true },
    render: (row) => h(NText, { code: true, monospace: true }, { default: () => row.ip }),
  },
  { title: 'Reason', key: 'reason', ellipsis: { tooltip: true } },
  {
    title: 'Expires',
    key: 'expiresAt',
    width: 160,
    render: (row) => row.expiresAt ? new Date(row.expiresAt).toLocaleString() : 'Never',
  },
  { title: 'Source', key: 'source', width: 100 },
  { title: 'Added', key: 'createdAt', width: 160, render: (row) => new Date(row.createdAt).toLocaleDateString() },
  {
    title: 'Actions',
    key: 'actions',
    width: 80,
    render: (row) => h(NPopconfirm, {
      onPositiveClick: () => deleteIP(row.id),
    }, {
      trigger: () => h(NButton, {
        size: 'small',
        quaternary: true,
        type: 'error',
      }, { default: () => h(NIcon, null, { default: () => h(TrashOutline) }) }),
      default: () => 'Remove this IP entry?',
    }),
  },
]

// Whitelist columns (same structure)
const whitelistColumns: DataTableColumns<IPEntry> = [...blacklistColumns]

async function fetchData() {
  loading.value = true

  try {
    const [blRes, wlRes] = await Promise.all([
      request.get('/ip-list', { params: { type: 'blacklist', page: blacklistPagination.page, page_size: blacklistPagination.pageSize } }),
      request.get('/ip-list', { params: { type: 'whitelist', page: whitelistPagination.page, page_size: whitelistPagination.pageSize } }),
    ])

    blacklistData.value = blRes.data.data || []
    blacklistPagination.itemCount = blRes.data.total || 0

    whitelistData.value = wlRes.data.data || []
    whitelistPagination.itemCount = wlRes.data.total || 0
  } catch (error) {
    console.error('Failed to fetch IP lists:', error)
    message.error('Failed to load IP lists')
  } finally {
    loading.value = false
  }
}

function handleTabChange(tab: string) {
  activeTab.value = tab
  // Data already loaded for both tabs
}

function handleBlacklistPageChange(page: number) {
  blacklistPagination.page = page
  fetchData()
}

function handleWhitelistPageChange(page: number) {
  whitelistPagination.page = page
  fetchData()
}

function showAddModal() {
  ipFormData.type = activeTab.value
  ipFormData.ip = ''
  ipFormData.reason = ''
  ipFormData.expiresAt = null
  addModal.value = true
}

function showBatchImportModal() {
  batchImportType.value = activeTab.value
  batchImportText.value = ''
  batchImportModal.value = true
}

async function handleSubmitIP() {
  try {
    await ipFormRef.value?.validate()
  } catch {
    return
  }

  submitting.value = true

  try {
    const payload: any = {
      ip: ipFormData.ip,
      type: ipFormData.type,
      reason: ipFormData.reason,
    }

    if (ipFormData.expiresAt && ipFormData.expiresAt[0]) {
      payload.expires_at = new Date(ipFormData.expiresAt[0]).toISOString()
    }

    await request.post('/ip-list', payload)
    message.success('IP entry added successfully')
    addModal.value = false
    fetchData()
  } catch (error: any) {
    message.error(error.response?.data?.message || 'Failed to add IP')
  } finally {
    submitting.value = false
  }
}

async function handleBatchImport() {
  if (!batchImportText.value.trim()) {
    message.warning('Please enter at least one IP address')
    return
  }

  importing.value = true

  try {
    const ips = batchImportText.value
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0)

    await request.post('/ip-list/batch-import', {
      type: batchImportType.value,
      ips,
    })

    message.success(`Successfully imported ${ips.length} IP addresses`)
    batchImportModal.value = false
    fetchData()
  } catch (error: any) {
    message.error(error.response?.data?.message || 'Failed to import IPs')
  } finally {
    importing.value = false
  }
}

async function deleteIP(id: number) {
  try {
    await request.delete(`/ip-list/${id}`)
    message.success('IP entry removed successfully')
    fetchData()
  } catch {
    message.error('Failed to remove IP entry')
  }
}

async function syncToRedis() {
  syncing.value = true
  try {
    await request.put('/ip-list/sync')
    message.success('All IP entries synced to Redis successfully')
  } catch {
    message.error('Failed to sync to Redis')
  } finally {
    syncing.value = false
  }
}

onMounted(() => {
  fetchData()
})
</script>

<style scoped>
.ip-list-page {
  max-width: 1400px;
}

.tab-content {
  margin-top: 16px;
}
</style>
