var loader = document.getElementById("page-preloader");
document.body.onload = function(){
	var timer = setInterval(function() {
		while (loader.style.opacity >= 0)
		{
			loader.style.opacity -= 0.01;
		}	
		

		loader.style.visibility = 'hidden';
		return;
	}, 50);
}