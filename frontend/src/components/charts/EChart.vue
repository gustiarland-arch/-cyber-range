<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { BarChart, LineChart, PieChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([BarChart, LineChart, PieChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])
const props = defineProps({ option: { type: Object, required: true }, height: { type: String, default: '260px' } })
const emit = defineEmits(['select'])
const el = ref(null)
let chart, ro

onMounted(() => {
  chart = echarts.init(el.value, null, { renderer: 'canvas' })
  chart.setOption(props.option)
  chart.on('click', (p) => emit('select', p))
  ro = new ResizeObserver(() => chart?.resize())
  ro.observe(el.value)
})
watch(() => props.option, (o) => chart?.setOption(o, true), { deep: true })
onBeforeUnmount(() => { ro?.disconnect(); chart?.dispose() })
</script>
<template><div ref="el" :style="{ height, width: '100%' }" /></template>
