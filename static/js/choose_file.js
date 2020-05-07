

document.getElementById('myfile').addEventListener('change', function(){
  if( this.value ){
  	document.getElementById('label').text = "File chosen!";
}};