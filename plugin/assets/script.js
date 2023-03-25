
//Grab all the hrefs on the current page
var y = [], linkVar = document.links;
for(var i=0; i<linkVar.length; i++) {
  y.push(linkVar[i].href);
}
console.log(y)
url = "http://127.0.0.1:5000/predict_api"
fetch(url, {
  method: 'POST',
  body: JSON.stringify({"URL":y}),
  headers: {
    'Content-Type': 'application/json',
  }
})
.then(response => response.json())
.then(data =>{
    linkVar = []
    data.response.forEach(function(object){
      if ((object.type=="Phishing")){
        linkVar.push(object.url)
      }
    })
    
    if (linkVar.length>0){
      alert("List of Phishing links:\n"+linkVar.join("\n"))

    }else{
      alert("You are good to go")
    }
    
})
