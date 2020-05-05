var loader = document.getElementById("page-preloader");
document.body.onload = function(){
	var timer = setInterval(function() {
		loader.style.opacity -= 0.01;
		if (loader.style.opacity == 0)
			clearInterval(timer);
			loader.style.visibility = 'hidden';
	}, 100);
}