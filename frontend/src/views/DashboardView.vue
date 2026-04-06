<template>
  <div class="dashboard">
    <!-- Statistics Cards -->
    <NGrid :cols="4" :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
      <NGi span="0:24 6:12 8:6">
        <NStatistic label="Total Requests" :value="stats.totalRequests">
          <template #prefix>
            <NIcon size="24" color="#18a058">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M3.5 18.49l6-6.01 4 4L22 6.92l-1.41-1.41-7.09 7.97-4-4L2 16.99z"/></svg>
            </NIcon>
          </template>
          <template #suffix>
            <span class="stat-trend up">
              <NIcon size="14"><TrendingUpOutline /></NIcon>
            </span>
          </template>
        </NStatistic>
      </NGi>

      <NGi span="0:24 6:12 8:6">
        <NStatistic label="Blocked Requests" :value="stats.blockedRequests">
          <template #prefix>
            <NIcon size="24" color="#d03050">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm5 11H7v-2h10v2z"/></svg>
            </NIcon>
          </template>
        </NStatistic>
      </NGi>

      <NGi span="0:24 6:12 8:6">
        <NStatistic label="QPS" :value="stats.qps.toFixed(1)">
          <template #prefix>
            <NIcon size="24" color="#f0a020">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M13 2.03v2.02c4.39.54 7.5 4.53 6.96 8.92-.46 3.64-3.32 6.53-6.96 6.96v2c5.5-.55 9.5-5.43 8.95-10.93-.45-4.75-4.22-8.52-8.95-8.97zM11 2.03C6.83 2.52 3.57 5.56 3.06 9.73c-.51 4.17 1.82 8.01 5.63 9.59L11 15.42V2.03z"/></svg>
            </NIcon>
          </template>
        </NStatistic>
      </NGi>

      <NGi span="0:24 6:12 8:6">
        <NStatistic label="Block Rate" :value="stats.blockRate.toFixed(2) + '%'">
          <template #prefix>
            <NIcon size="24" color="#4098fc">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M16 6l2.29 2.29-4.88 4.88-4-4L2 16.59 3.41 18l6-6 4 4 6.3-6.29L22 12V6z"/></svg>
            </NIcon>
          </template>
        </NStatistic>
      </NGi>
    </NGrid>

    <!-- Secondary Stats -->
    <NGrid :cols="4" :x-gap="16" :y-gap="16" style="margin-top: 16px;" responsive="screen" item-responsive>
      <NGi span="0:24 6:12 8:6">
        <NCard :bordered="false" hoverable class="mini-stat-card">
          <NStatistic label="Active Rules" :value="stats.activeRules" />
        </NCard>
      </NGi>
      <NGi span="0:24 6:12 8:6">
        <NCard :bordered="false" hoverable class="mini-stat-card">
          <NStatistic label="Blacklisted IPs" :value="stats.blacklistedIPs" />
        </NCard>
      </NGi>
      <NGi span="0:24 6:12 8:6">
        <NCard :bordered="false" hoverable class="mini-stat-card">
          <NStatistic label="Whitelisted IPs" :value="stats.whitelistedIPs" />
        </NCard>
      </NGi>
      <NGi span="0:24 6:12 8:6">
        <NCard :bordered="false" hoverable class="mini-stat-card">
          <NStatistic label="Rate Limited" :value="stats.rateLimitedReqs" />
        </NCard>
      </NGi>
    </NGrid>

    <!-- Charts and Lists -->
    <NSpace vertical :size="16" style="margin-top: 16px;">
      <NGrid :x-gap="16" :y-gap="16" cols="2" responsive="screen" item-responsive>
        <NGi span="0:24 12:12">
          <NCard title="Recent Security Events" :bordered="false" size="small">
            <template #header-extra>
              <NButton quaternary size="small" @click="refreshData">
                <template #icon>
                  <NIcon><RefreshOutline /></NIcon>
                </template>
                Refresh
              </NButton>
            </template>

            <NScrollbar style="max-height: 400px;">
              <NTimeline v-if="recentEvents.length > 0">
                <NTimelineItem
                  v-for="event in recentEvents"
                  :key="event.id"
                  :type="getEventType(event.wafAction)"
                  :title="event.method + ' ' + truncate(event.uri, 60)"
                  :time="formatTime(event.timestamp)"
                  :content="event.wafRule || event.wafAction"
                />
              </NTimeline>
              <NEmpty v-else description="No recent security events" />
            </NScrollbar>
          </NCard>
        </NGi>

        <NGi span="0:24 12:12">
          <NCard title="Top Attack Types" :bordered="false" size="small">
            <NList v-if="topAttacks.length > 0" hoverable clickable>
              <NListItem v-for="(attack, index) in topAttacks" :key="attack.ruleName">
                <template #prefix>
                  <NBadge :value="index + 1" :type="index < 3 ? 'error' : 'info'" />
                </template>
                <NThing :title="attack.ruleName || 'Unknown Attack'" :description="`${attack.count} occurrences`">
                  <template #header-extra>
                    <NProgress
                      type="line"
                      :percentage="attack.percentage"
                      :show-indicator="false"
                      status="error"
                      style="width: 80px;"
                    />
                  </template>
                </NThing>
              </NListItem>
            </NList>
            <NEmpty v-else description="No attack data available" />
          </NCard>
        </NGi>
      </NGrid>
    </NSpace>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, reactive } from 'vue'
import {
  NGrid,
  NGi,
  NStatistic,
  NCard,
  NSpace,
  NScrollbar,
  NTimeline,
  NTimelineItem,
  NEmpty,
  NList,
  NListItem,
  NThing,
  NProgress,
  NBadge,
  NButton,
  NIcon,
  useMessage,
} from 'naive-ui'
import { TrendingUpOutline, RefreshOutline } from '@vicons/ionicons5'
import request from '@/api/request'

interface DashboardStats {
  totalRequests: number
  blockedRequests: number
  rateLimitedReqs: number
  qps: number
  blockRate: number
  activeRules: number
  blacklistedIPs: number
  whitelistedIPs: number
  uptimeSeconds: number
}

interface RecentEvent {
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
}

interface TopAttackStat {
  ruleName: string
  count: number
  percentage: number
}

const message = useMessage()

const stats = reactive<DashboardStats>({
  totalRequests: 0,
  blockedRequests: 0,
  rateLimitedReqs: 0,
  qps: 0,
  blockRate: 0,
  activeRules: 0,
  blacklistedIPs: 0,
  whitelistedIPs: 0,
  uptimeSeconds: 0,
})

const recentEvents = ref<RecentEvent[]>([])
const topAttacks = ref<TopAttackStat[]>([])

let refreshTimer: ReturnType<typeof setInterval> | null = null

async function fetchDashboardData() {
  try {
    const [statsRes, eventsRes, attacksRes] = await Promise.all([
      request.get('/dashboard/stats'),
      request.get('/dashboard/recent-events?limit=10'),
      request.get('/dashboard/top-attacks?limit=8'),
    ])

    Object.assign(stats, statsRes.data)
    recentEvents.value = eventsRes.data.data || []
    topAttacks.value = attacksRes.data.data || []
  } catch (error) {
    console.error('Failed to fetch dashboard data:', error)
  }
}

function refreshData() {
  fetchDashboardData()
  message.success('Dashboard refreshed')
}

function getEventType(action: string): 'success' | 'error' | 'warning' | 'info' | 'default' {
  switch (action) {
    case 'deny': return 'error'
    case 'rate_limited': return 'warning'
    default: return 'success'
  }
}

function formatTime(timestamp: string): string {
  return new Date(timestamp).toLocaleString()
}

function truncate(str: string, len: number): string {
  return str.length > len ? str.substring(0, len) + '...' : str
}

onMounted(() => {
  fetchDashboardData()
  refreshTimer = setInterval(fetchDashboardData, 5000)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<style scoped>
.dashboard {
  max-width: 1400px;
}

.mini-stat-card {
  background: linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%);
}

.stat-trend.up {
  color: #18a058;
  display: inline-flex;
  align-items: center;
  margin-left: 4px;
}
</style>
