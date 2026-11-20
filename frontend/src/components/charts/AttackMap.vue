<script setup>
// World map (Natural Earth 110m via world-atlas, bundled, no external tiles) with attack sources as scaled points.
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { EffectScatterChart, ScatterChart } from 'echarts/charts'
import { GeoComponent, TooltipComponent, VisualMapComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { feature } from 'topojson-client'
import world from 'world-atlas/countries-110m.json'

echarts.use([GeoComponent, ScatterChart, EffectScatterChart, TooltipComponent, VisualMapComponent, CanvasRenderer])
if (!echarts.getMap('cr-world')) echarts.registerMap('cr-world', feature(world, world.objects.countries))

const props = defineProps({ points: { type: Array, default: () => [] }, height: { type: String, default: '440px' } })
const emit = defineEmits(['select'])
const el = ref(null)
let chart, ro
const SEV = ['#7f8ea3', '#3b9eff', '#f5b941', '#f08a3c', '#f05262']

function option() {
  const max = Math.max(1, ...props.points.map((p) => p.events))
  const data = props.points.map((p) => ({ name: p.ip, value: [p.lon, p.lat, p.events], p, itemStyle: { color: SEV[p.max_severity] || SEV[0] },
    symbolSize: 6 + Math.round(Math.sqrt(p.events / max) * 22) }))
  const top = [...data].sort((a, b) => b.value[2] - a.value[2]).slice(0, 5)
  return {
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item', formatter: (x) => (x.data?.p ? `${x.data.p.ip}<br/>${[x.data.p.city, x.data.p.country_name].filter(Boolean).join(', ') || '—'}<br/>${x.data.p.events} event` : x.name) },
    geo: { map: 'cr-world', roam: true, zoom: 1.15, itemStyle: { areaColor: '#19283d', borderColor: '#2b3d57' }, emphasis: { itemStyle: { areaColor: '#22344f' }, label: { show: false } } },
    series: [
      { type: 'scatter', coordinateSystem: 'geo', data, symbolSize: (v, d) => d.data.symbolSize },
      { type: 'effectScatter', coordinateSystem: 'geo', data: top, symbolSize: (v, d) => d.data.symbolSize, rippleEffect: { scale: 3, brushType: 'stroke' }, zlevel: 1 },
    ],
  }
}
onMounted(() => {
  chart = echarts.init(el.value, null, { renderer: 'canvas' })
  chart.setOption(option())
  chart.on('click', (x) => x.data?.p && emit('select', x.data.p))
  ro = new ResizeObserver(() => chart?.resize())
  ro.observe(el.value)
})
watch(() => props.points, () => chart?.setOption(option(), true), { deep: true })
onBeforeUnmount(() => { ro?.disconnect(); chart?.dispose() })
</script>
<template><div ref="el" :style="{ height, width: '100%' }" data-test="attack-map" /></template>
