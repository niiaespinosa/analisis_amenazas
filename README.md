# Inteligencia de amenazas
Este repositorio tiene como objetivo funcionar a modo de proyecto entry-level relativo a Ciencia de Datos y Ciberseguridad, así como familiarizarse con la inteligencia de amenazas.  
El código actualizándose en tiempo real es:  
https://colab.research.google.com/drive/1n1M5qlvTx3KaI0c-xxQSMDstLjXQhxjI#scrollTo=gqsBMDhTr8Hd  
# Objetivo  
Generar un flujo de trabajo capaz de automatizar reportes de inteligencia de amenazas a partir de una base de datos sobre IOC.  

# Herramientas y librerías
Base de datos de ThreatFox  
* Google Colab  
* Python  
* Pandas  
* MatPlotlib  
* Seaborn  
* Lets Plot  
* Markdown  

# Nota
El análisis mostrado en Jupyter Notebook tiene como propósito guiar a personas con poca experiencia a realizar su primer proyecto, no como un análisis completo, se recomienda explorar otras variables y tipos de gráfico.  
Siéntase libre de utilizar la información proporcionada aquí.  

Los datos se obtuvieron a través de ThreatFox. 
Se agradece el acceso a abuse.ch:  
https://abuse.ch/  
https://threatfox.abuse.ch/  

# Procedimiento
Se llevó a cabo un flujo de análisis exploratorio e ingeniería sobre los datos. El aprendizaje guiado se encuentra en el notebook ('datos_amenazas.ipynb')  

# Resultados
El reporte automático generado se encuentra en 'reporte_amenazas.md'. Este tipo se flujo de trabajo puede generarse fácilmente para distintas bases de datos. No obstante, es importante elaborarlo cuidadosamente. Aún así, posee un gran potencial para identificar y analizar registros de indicadores de compromiso de forma automatizada.  
Por otro lado, este conjunto está limitado a que los IOC sean identificados y reportados, por lo que puede estar sesgado con respecto a la realidad. Asimismo, la cantidad de datos es demasiado reducida como para identificar patrones y comportamientos habituales de los cibercriminales. De cualquier manera, el análisis es apropiado para acercarse a interacciones con información similar.  
