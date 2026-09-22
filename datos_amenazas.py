# -*- coding: utf-8 -*-
"""datos_amenazas.ipynb
Original file is located at
    https://colab.research.google.com/drive/1n1M5qlvTx3KaI0c-xxQSMDstLjXQhxjI
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import date
from lets_plot import *
import os
# ... tus otros imports ...

# carpeta para imágenes
carpeta_img = "images"
os.makedirs(carpeta_img, exist_ok=True)

# Inicializamos lets-plot (necesario para el entorno de Python)
LetsPlot.setup_html()

# Si se está ejecutando desde Google Colab
try:
    from google.colab import files
    entorno_colab = True
except ImportError:
    entorno_colab = False

# CARGA Y LIMPIEZA
datos = pd.read_csv("full.csv", comment='#', quotechar='"', skipinitialspace=True)

# Filtro por nivel de confianza
datos = datos[datos['confidence_level'] > 50]

# Manejo de fechas e imputación de nulos
datos["first_seen_utc"] = pd.to_datetime(datos['first_seen_utc'], errors='coerce')
datos["last_seen_utc"] = pd.to_datetime(datos['last_seen_utc'], errors='coerce')
datos["secuencia"] = datos["last_seen_utc"].fillna(datos["first_seen_utc"])

# Optimización: Convertimos a categorías para ahorrar memoria
cols_categoricas = ["ioc_type", "threat_type"]
datos[cols_categoricas] = datos[cols_categoricas].astype('category')

# INGENIERÍA DE CARACTERÍSTICAS
# Extraemos todas las variables de tiempo que necesitaremos
datos["dia"] = datos["secuencia"].dt.date
datos["dia_week"] = datos["secuencia"].dt.day_of_week
datos["hora"] = datos["secuencia"].dt.hour
datos["mes"] = datos["secuencia"].dt.month_name()

# Convertimos la secuencia en el índice principal para poder usar resample()
datos = datos.set_index('secuencia')

# ANÁLISIS ESTADÍSTICO

# Estadísticas por Día
ataques_diarios = datos.resample('D').size().reset_index(name='total_ataques')
ataques_diarios['dia_week'] = ataques_diarios['secuencia'].dt.day_of_week
dias_nombres = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo']
ataques_diarios['nombre_dia'] = ataques_diarios['dia_week'].map(lambda x: dias_nombres[x])

estadisticas_semana = ataques_diarios.groupby('dia_week')['total_ataques'].agg(['sum','mean', 'std', 'min', 'max']).reset_index()
estadisticas_semana['dia_week'] = estadisticas_semana['dia_week'].map(lambda x: dias_nombres[x])
estadisticas_semana.columns = ['Día de la Semana', 'Total', 'Promedio', 'Desviación Estándar', 'Mínimo', 'Máximo']
print("Resumen estadístico por día de la semana:\n", estadisticas_semana)

# Estadísticas por Hora
ataques_hora = datos.resample('h').size().reset_index(name='total_ataques')
ataques_hora['hora'] = ataques_hora['secuencia'].dt.hour

estadisticas_hora = ataques_hora.groupby('hora')['total_ataques'].agg(['sum','mean', 'std', 'min', 'max']).reset_index()
estadisticas_hora.columns = ['Hora', 'Total', 'Promedio', 'Desviación Estándar', 'Mínimo', 'Máximo']
print("\nResumen estadístico por hora:\n", estadisticas_hora.head())

#GRÁFICOS

# Gráfico 1: Barras de Tipos de Amenaza
agrupados = datos['threat_type'].value_counts().reset_index()
agrupados.columns = ['threat_type', 'cantidad_detectada']

fig1, ax1 = plt.subplots(figsize=(10, 6))
barras = ax1.bar(agrupados["threat_type"], agrupados["cantidad_detectada"])
ax1.set_title("Cantidad de Amenazas Detectadas por Tipo (ThreatFox)", fontsize=14, pad=15)
ax1.set_xlabel("Tipo de Amenaza", fontsize=12)
ax1.set_ylabel("Cantidad de Indicadores (IOCs)", fontsize=12)
ax1.set_xticklabels(agrupados["threat_type"], rotation=45, ha='right')
ax1.bar_label(barras, padding=3, fontsize=10, color='black')
fig1.tight_layout()
fig1.savefig(f"{carpeta_img}/grafico_barras.png", bbox_inches='tight', transparent=True)
plt.close(fig1)

# Gráfico 2: Pastel (Top 5)
fig2, ax2 = plt.subplots(figsize=(10, 6))
top_5_amenazas = agrupados.head(5)
ax2.pie(x=top_5_amenazas['cantidad_detectada'], labels=top_5_amenazas["threat_type"], autopct='%1.1f%%')
ax2.set_title("Top 5 de Amenazas Detectadas", fontsize=14, pad=15)
fig2.savefig(f"{carpeta_img}/grafico_pastel.png", bbox_inches='tight', transparent=True)
plt.close(fig2)

# Gráfico 3: Evolución de Líneas
totales_dia = datos.groupby("dia").size().reset_index(name="count")
fig3, ax3 = plt.subplots(figsize=(10, 6))
ax3.plot(totales_dia["dia"], totales_dia['count'], marker='.', color='firebrick')
ax3.set_title("Cantidad de amenazas por día")
ax3.set_xlabel("Fecha")
ax3.set_ylabel("Registros de IOC")
ax3.grid(True, linestyle='--', alpha=0.7)
fig3.tight_layout()
fig3.savefig(f"{carpeta_img}/grafico_lineas.png", bbox_inches='tight', transparent=True)
plt.close(fig3)

# Gráfico 4: Cajas por Día de la Semana
fig4, ax4 = plt.subplots(figsize=(10, 6))
sns.boxplot(data=ataques_diarios, x='nombre_dia', y='total_ataques', order=dias_nombres, palette='viridis', ax=ax4)
ax4.set_title("Distribución Estadística de Amenazas por Día de la Semana", fontsize=14, pad=15)
ax4.set_xlabel("Día de la Semana", fontsize=12)
ax4.set_ylabel("Volumen de Ataques (Diarios)", fontsize=12)
ax4.yaxis.grid(True, linestyle='--', alpha=0.7)
fig4.tight_layout()
fig4.savefig(f"{carpeta_img}/grafico_cajas.png", bbox_inches='tight', transparent=True)
plt.close(fig4)

# Gráfico 5: Cajas por Hora
fig5, ax5 = plt.subplots(figsize=(10, 6))
sns.boxplot(data=ataques_hora, x='hora', y='total_ataques', palette='viridis', ax=ax5)
ax5.set_title("Distribución Estadística de Amenazas por Hora", fontsize=14, pad=15)
ax5.set_xlabel("Hora del Día", fontsize=12)
ax5.set_ylabel("Volumen de Ataques (Por Hora)", fontsize=12)
ax5.set_ylim(top=100, bottom=-10)
ax5.yaxis.grid(True, linestyle='--', alpha=0.7)
fig5.tight_layout()
fig5.savefig(f"{carpeta_img}/grafico_cajas_hora.png", bbox_inches='tight', transparent=True) # Nombre corregido
plt.close(fig5)

# Gráfico 6: Lets-Plot (Malware Apilado)
top_20_familias = datos['fk_malware'].value_counts().head(20).index
datos['fk_malware_limpio'] = datos['fk_malware'].astype(str)
datos['fk_malware_limpio'] = datos['fk_malware_limpio'].where(datos['fk_malware_limpio'].isin(top_20_familias), 'Otros')

grafico = (
    ggplot(datos, aes(x=as_discrete('fk_malware_limpio', order_by='..count..', order=-1), fill='ioc_type')) +
    geom_bar(color="black", size=0.2) +
    labs(
        title="Top 20 Familias de Malware por Tipo de IOC",
        x="Familia de Malware", y="Cantidad de Registros", fill="Tipo de Amenaza"
    ) +
    theme(
        axis_text_x=element_text(angle=90, hjust=1),
        plot_background=element_rect(fill='transparent', color='transparent'),
        panel_background=element_rect(fill='transparent', color='transparent')
    )
)
ggsave(grafico, "malware_apilado.png", path=carpeta_img, w=10, h=6, unit='in', dpi=300)

#SI ESTAMOS EN COLAB
if entorno_colab:
    print("\n--- Descargando imágenes ---")
    files.download(f"{carpeta_img}/grafico_barras.png")
    files.download(f"{carpeta_img}/grafico_lineas.png")
    files.download(f"{carpeta_img}/grafico_pastel.png")
    files.download(f"{carpeta_img}/grafico_cajas.png")
    files.download(f"{carpeta_img}/grafico_cajas_horas.png")
    files.download(f"{carpeta_img}/malware_apilado.png")

#GENERAR REPORTE AUTOMÁTCIO 

columnas_interes = ["ioc_type", "fk_malware", "threat_type", "dia", "hora", "dia_week", "mes"]
los_mas_frecuentes = datos[columnas_interes].astype('category').describe().loc['top']

# Uso correcto de comillas en las f-strings
titulo = f"Análisis de IOC entre {datos['last_seen_utc'].min()} y {datos['last_seen_utc'].max()}"
print("Título del reporte:", titulo)

fecha_hoy = date.today().strftime("%Y-%m-%d")
total_iocs = len(datos)

plantilla_markdown = f"""# Reporte de Inteligencia de Amenazas (ThreatFox)
**Fecha de generación automática:** {fecha_hoy}

## Resumen
Durante el periodo analizado, se procesaron un total de **{total_iocs:,}** indicadores de compromiso (IOCs).
El análisis revela que el mes con mayor actividad maliciosa fue **{los_mas_frecuentes['mes']}**.

La táctica preferida por los adversarios (Threat Type) fue **{los_mas_frecuentes['threat_type']}**, utilizada principalmente para distribuir la familia de malware **{los_mas_frecuentes['fk_malware']}**. La infraestructura base más utilizada para estos ataques (IOC Type) fue **{los_mas_frecuentes['ioc_type']}**.

---

## Análisis Temporal de Actividad
A continuación, se presenta la evolución histórica de las amenazas. El gráfico de cajas y bigotes permite identificar si los atacantes tienen un patrón de trabajo centrado en días laborales o fines de semana, o alguno relacionado con las horas, así como los picos atípicos (outliers) de campañas masivas.

<p align="center">
  <img src="{carpeta_img}/grafico_lineas.png" width="600">
</p>

<p align="center">
  <img src="{carpeta_img}/grafico_cajas.png" width="600">
</p>

<p align="center">
  <img src="{carpeta_img}/grafico_cajas_hora.png" width="600">
</p>

---

## Familias de Malware, IOC y tipo de amenaza

En primer lugar, es importante detectar el tipo de amenaza más frecuente, para identificar algunas medidas de seguridad necesarias.
<p align="center">
  <img src="{carpeta_img}/grafico_barras.png" width="600">
</p>

El siguiente gráfico desglosa las familias de malware predominantes y el tipo de infraestructura que las sostiene. Las familias fuera del top 20 han sido agrupadas en la categoría "Otros" para limpiar el ruido estadístico.
<p align="center">
  <img src="{carpeta_img}/malware_apilado.png" width="600">
</p>

## Importante  
Métricas como el día o la hora con más ocurrencias pueden resultar útiles, pero
las medidas estadísticas siempre deben ser interpretadas de forma cuidadosa y tomando en
cuenta partes del contexto, como medidas de tendencia central y dispersión.  
Además, cada conjunto posee sus propias características, y debe establecerse un flujo de
trabajo particular para cada uno de ellos.  

*Reporte generado automáticamente mediante Python y Pandas. Datos extraídos de abuse.ch (ThreatFox).*
abuse.ch. (2026). ThreatFox. Recuperado el {datos["last_seen_utc"].max().date()}, de https://threatfox.abuse.ch/
"""

with open("reporte_amenazas.md", "w", encoding="utf-8") as archivo:
    archivo.write(plantilla_markdown)

if entorno_colab:
    files.download("reporte_amenazas.md")

