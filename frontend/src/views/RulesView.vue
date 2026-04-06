<template>
  <div class="rules-page">
    <NCard :bordered="false">
      <template #header>
        <NSpace align="center" justify="space-between" style="width: 100%;">
          <span>Rules Management</span>
          <NSpace>
            <NInput
              v-model:value="searchQuery"
              placeholder="Search rules..."
              clearable
              style="width: 240px;"
              @input="handleSearch"
            >
              <template #prefix>
                <NIcon><SearchOutline /></NIcon>
              </template>
            </NInput>

            <NSelect
              v-model:value="filterType"
              :options="typeOptions"
              placeholder="All Types"
              clearable
              style="width: 180px;"
              @update:value="fetchRules"
            />

            <NButton type="primary" @click="showCreateModal">
              <template #icon>
                <NIcon><AddOutline /></NIcon>
              </template>
              Create Rule
            </NButton>

            <NButton @click="syncRulesToRedis" :loading="syncing">
              <template #icon>
                <NIcon><SyncOutline /></NIcon>
              </template>
              Sync to Redis
            </NButton>
          </NSpace>
        </NSpace>
      </template>

      <!-- Rules Table -->
      <NDataTable
        :columns="columns"
        :data="rules"
        :loading="loading"
        :pagination="pagination"
        :bordered="false"
        striped
        size="small"
        @update:page="handlePageChange"
      />
    </NCard>

    <!-- Create/Edit Modal -->
    <NModal
      v-model:show="showModal"
      :title="editingRule ? 'Edit Rule' : 'Create New Rule'"
      preset="card"
      style="width: 600px;"
      :mask-closable="false"
    >
      <NForm
        ref="formRef"
        :model="formData"
        :rules="formRules"
        label-placement="left"
        label-width="auto"
      >
        <NFormItem label="Name" path="name">
          <NInput v-model:value="formData.name" placeholder="Rule name" />
        </NFormItem>

        <NFormItem label="Description" path="description">
          <NInput
            v-model:value="formData.description"
            type="textarea"
            placeholder="Rule description"
            :rows="2"
          />
        </NFormItem>

        <NFormItem label="Type" path="type">
          <NSelect
            v-model:value="formData.type"
            :options="ruleTypeOptions"
            placeholder="Select rule type"
          />
        </NFormItem>

        <NFormItem label="Pattern (Regex)" path="pattern">
          <NInput
            v-model:value="formData.pattern"
            type="textarea"
            placeholder="Regular expression pattern"
            :rows="3"
          />
        </NFormItem>

        <NGrid :cols="2" :x-gap="16">
          <NGi>
            <NFormItem label="Action" path="action">
              <NSelect
                v-model:value="formData.action"
                :options="actionOptions"
                placeholder="Action when matched"
              />
            </NFormItem>
          </NGi>

          <NGi>
            <NFormItem label="Severity" path="severity">
              <NSelect
                v-model:value="formData.severity"
                :options="severityOptions"
                placeholder="Severity level"
              />
            </NFormItem>
          </NGi>
        </NGrid>

        <NFormItem label="Priority" path="priority">
          <NSlider
            v-model:value="formData.priority"
            :min="1"
            :max="1000"
            :step="1"
            style="margin-top: 8px;"
          />
        </NFormItem>
      </NForm>

      <template #footer>
        <NSpace justify="end">
          <NButton @click="showModal = false">Cancel</NButton>
          <NButton type="primary" :loading="submitting" @click="handleSubmit">
            {{ editingRule ? 'Update' : 'Create' }}
          </NButton>
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
  NInput,
  NButton,
  NIcon,
  NDataTable,
  NModal,
  NForm,
  NFormItem,
  NSelect,
  NSlider,
  useMessage,
  type FormInst,
  type DataTableColumns,
} from 'naive-ui'
import {
  SearchOutline,
  AddOutline,
  SyncOutline,
  CreateOutline,
  TrashOutline,
} from '@vicons/ionicons5'
import request from '@/api/request'

interface Rule {
  id: number
  name: string
  description: string
  type: string
  pattern: string
  action: string
  severity: string
  priority: number
  enabled: boolean
  version: number
  createdAt: string
}

const message = useMessage()

const loading = ref(false)
const syncing = ref(false)
const searchQuery = ref('')
const filterType = ref<string | null>(null)
const showModal = ref(false)
const submitting = ref(false)
const editingRule = ref<Rule | null>(null)

const rules = ref<Rule[]>([])
const pagination = reactive({
  page: 1,
  pageSize: 20,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 20, 50],
})

const formRef = ref<FormInst | null>(null)
const formData = reactive({
  name: '',
  description: '',
  type: '',
  pattern: '',
  action: 'deny',
  severity: 'medium',
  priority: 100,
})

const formRules = {
  name: { required: true, message: 'Name is required', trigger: 'blur' },
  type: { required: true, message: 'Type is required', trigger: 'change' },
  pattern: { required: true, message: 'Pattern is required', trigger: 'blur' },
  action: { required: true, message: 'Action is required', trigger: 'change' },
}

// Options
const ruleTypeOptions = [
  { label: 'SQL Injection', value: 'sql_injection' },
  { label: 'XSS', value: 'xss' },
  { label: 'CC Attack', value: 'cc_attack' },
  { label: 'Path Traversal', value: 'path_traversal' },
  { label: 'Command Injection', value: 'command_injection' },
  { label: 'SSI Injection', value: 'ssi_injection' },
  { label: 'XXE Injection', value: 'xxe_injection' },
  { label: 'Custom Regex', value: 'custom_regex' },
]

const actionOptions = [
  { label: 'Deny', value: 'deny' },
  { label: 'Allow', value: 'allow' },
  { label: 'Log Only', value: 'log_only' },
]

const severityOptions = [
  { label: 'Low', value: 'low' },
  { label: 'Medium', value: 'medium' },
  { label: 'High', value: 'high' },
  { label: 'Critical', value: 'critical' },
]

const typeOptions = [...ruleTypeOptions]

// Table columns
const columns: DataTableColumns<Rule> = [
  { title: 'ID', key: 'id', width: 60, sorter: 'default' },
  { title: 'Name', key: 'name', ellipsis: { tooltip: true }, width: 150 },
  { title: 'Type', key: 'type', width: 130, render: (row) => formatType(row.type) },
  { title: 'Pattern', key: 'pattern', ellipsis: { tooltip: true } },
  { title: 'Action', key: 'action', width: 90, render: (row) => formatAction(row.action) },
  { title: 'Severity', key: 'severity', width: 90, render: (row) => formatSeverity(row.severity) },
  { title: 'Priority', key: 'priority', width: 80, sorter: 'default' },
  {
    title: 'Enabled',
    key: 'enabled',
    width: 80,
    render: (row) => h(NSwitch, {
      value: row.enabled,
      onUpdate: () => toggleEnabled(row),
    }),
  },
  { title: 'Version', key: 'version', width: 70 },
  {
    title: 'Actions',
    key: 'actions',
    width: 120,
    render: (row) => h(NSpace, null, {
      default: () => [
        h(NButton, {
          size: 'small',
          quaternary: true,
          onClick: () => showEditModal(row),
        }, { default: () => h(NIcon, null, { default: () => h(CreateOutline) }) }),

        h(NPopconfirm, {
          onPositiveClick: () => deleteRule(row.id),
        }, {
          trigger: () => h(NButton, {
            size: 'small',
            quaternary: true,
            type: 'error',
          }, { default: () => h(NIcon, null, { default: () => h(TrashOutline) }) }),
          default: () => 'Delete this rule?',
        }),
      ],
    }),
  },
]

async function fetchRules() {
  loading.value = true

  try {
    const params: Record<string, any> = {
      page: pagination.page,
      page_size: pagination.pageSize,
    }

    if (filterType.value) params.type = filterType.value
    if (searchQuery.value) params.search = searchQuery.value

    const response = await request.get('/rules', { params })
    const data = response.data

    rules.value = data.data || []
    pagination.itemCount = data.total || 0
  } catch (error) {
    console.error('Failed to fetch rules:', error)
    message.error('Failed to load rules')
  } finally {
    loading.value = false
  }
}

function handlePageChange(page: number) {
  pagination.page = page
  fetchRules()
}

function handleSearch() {
  pagination.page = 1
  fetchRules()
}

function resetForm() {
  formData.name = ''
  formData.description = ''
  formData.type = ''
  formData.pattern = ''
  formData.action = 'deny'
  formData.severity = 'medium'
  formData.priority = 100
  editingRule.value = null
}

function showCreateModal() {
  resetForm()
  showModal.value = true
}

function showEditModal(rule: Rule) {
  editingRule.value = rule
  formData.name = rule.name
  formData.description = rule.description
  formData.type = rule.type
  formData.pattern = rule.pattern
  formData.action = rule.action
  formData.severity = rule.severity
  formData.priority = rule.priority
  showModal.value = true
}

async function handleSubmit() {
  try {
    await formRef.value?.validate()
  } catch {
    return
  }

  submitting.value = true

  try {
    if (editingRule.value) {
      await request.put(`/rules/${editingRule.value.id}`, formData)
      message.success('Rule updated successfully')
    } else {
      await request.post('/rules', formData)
      message.success('Rule created successfully')
    }

    showModal.value = false
    fetchRules()
  } catch (error: any) {
    message.error(error.response?.data?.message || 'Operation failed')
  } finally {
    submitting.value = false
  }
}

async function toggleEnabled(rule: Rule) {
  try {
    await request.put(`/rules/${rule.id}`, { enabled: !rule.enabled })
    message.success(`Rule ${rule.name} ${!rule.enabled ? 'enabled' : 'disabled'}`)
    fetchRules()
  } catch {
    message.error('Failed to update rule status')
  }
}

async function deleteRule(id: number) {
  try {
    await request.delete(`/rules/${id}`)
    message.success('Rule deleted successfully')
    fetchRules()
  } catch {
    message.error('Failed to delete rule')
  }
}

async function syncRulesToRedis() {
  syncing.value = true
  try {
    await request.put('/rules/sync')
    message.success('All rules synced to Redis successfully')
  } catch {
    message.error('Failed to sync rules to Redis')
  } finally {
    syncing.value = false
  }
}

// Format helpers
function formatType(type: string): any {
  return h(NTag, {
    type: getTypeTagType(type),
    size: 'small',
    round: true,
    bordered: false,
  }, { default: () => type.replace('_', ' ') })
}

function formatAction(action: string): any {
  return h(NTag, {
    type: action === 'deny' ? 'error' : action === 'allow' ? 'success' : 'warning',
    size: 'small',
    round: true,
    bordered: false,
  }, { default: () => action.replace('_', ' ') })
}

function formatSeverity(severity: string): any {
  const colors: Record<string, string> = {
    low: 'success',
    medium: 'warning',
    high: 'error',
    critical: 'error',
  }

  return h(NTag, {
    type: colors[severity] || 'default',
    size: 'small',
    round: true,
    bordered: false,
  }, { default: () => severity })
}

function getTypeTagType(type: string): 'info' | 'success' | 'warning' | 'error' | 'default' {
  const map: Record<string, any> = {
    sql_injection: 'error',
    xss: 'error',
    cc_attack: 'warning',
    path_traversal: 'warning',
    command_injection: 'error',
    ssi_injection: 'info',
    xxe_injection: 'error',
    custom_regex: 'info',
  }
  return map[type] || 'default'
}

onMounted(() => {
  fetchRules()
})
</script>

<style scoped>
.rules-page {
  max-width: 1400px;
}
</style>
