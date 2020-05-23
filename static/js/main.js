let themeButton = document.querySelector('#change-theme-label');
const page = document.querySelector('.page'),
    themeIcon = document.querySelector('#change-theme-icon');

if (localStorage.getItem("theme") === "light-theme") {
    themeIcon.className = "fas fa-sun";
}
else if (localStorage.getItem("theme") == null) {
    localStorage.setItem("theme", "light-theme");
    themeIcon.className = "fas fa-sun";
}
else {
    themeIcon.className = "fa fa-moon-o";
}

page.className = "page " + localStorage.getItem("theme");

themeButton.onclick = function() {
    page.classList.toggle('light-theme');
    page.classList.toggle('dark-theme');
    localStorage.setItem("theme", page.classList.value.split(' ')[1]);
    if (localStorage.getItem("theme") === "light-theme") {
        themeIcon.className = "fas fa-sun";
    }
    else {
        themeIcon.className = "fa fa-moon-o";
    }
}