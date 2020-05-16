let themeButton = document.querySelector('#change-theme-label')
const page = document.querySelector('.page')


if (!localStorage.getItem("theme")) {
    localStorage.setItem("theme", "light-theme")
}

page.className = "page " + localStorage.getItem("theme")

themeButton.onclick = function() {
    page.classList.toggle('light-theme')
    page.classList.toggle('dark-theme')
    localStorage.setItem("theme", page.classList.value.split(' ')[1]);
}