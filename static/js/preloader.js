while ((amount_videos >= already_loaded)) {
	for (var oneVideo of videos) {
		console.log(oneVideo.readyState)
		if (oneVideo.readyState) {
			console.log(`${typeof percents} - ${typeof already_loaded}`)
			percents = percents + progress_step
			already_loaded++;
			perc_loader.textContent = `\n      ${percents.toFixed()}%\n    `
		}
	}
}

const temp_videos = document.querySelectorAll('video')

var videos = [];
for (var i of temp_videos) {
	videos.push(i)
}

var loader = document.getElementById("page-preloader"),
	perc_loader = document.querySelector('#preloader_proc'),
	percents = 0,
	amount_videos = videos.length,
	already_loaded = 0,
	i = 0;

const progress_step = (1 / amount_videos * 100)

var loadingPercTimer = setInterval(() => {
	if (videos.length === 0) {
		clearInterval(loadingPercTimer)
	}
	else
	{
		if (videos[i].readyState) {
			percents += progress_step
			perc_loader.textContent = `\n      ${percents.toFixed()}%\n    `
			videos.splice(i, 1)
		}

		i = (i + 1) % videos.length
	}


}, 100)

document.body.onload = function(){
	perc_loader.textContent = `\n      100%\n    `
	clearInterval(loadingPercTimer);
	var timer = setInterval(function() {
		loader.style.opacity -= 0.01;

		if (loader.style.opacity < 0) {
			clearInterval(timer)
			loader.style.visibility = 'hidden';
			return;
		}
	}, 50);
}