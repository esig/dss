function activeHTML()
{
	var str = "abbr,article,aside,audio,bb,canvas,datagrid,datalist,details,dialog,eventsource,figure,footer,header,mark,menu,meter,nav,output,progress,section,time,video";
	var list = str.split(",");
	for(i = 0; i < list.length; i++)
    {
      document.createElement(list[i]);
    }
}

