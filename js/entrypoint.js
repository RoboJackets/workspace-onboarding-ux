const app = Elm.Main.init(
    {
        flags: {
            serverData: window.serverData,
            localData: localStorage.getItem("formFields"),
        }
    }
);

app.ports.saveToLocalStorage.subscribe(function (message) {
    localStorage.setItem("formFields", message);
    app.ports.localStorageSaved.send(true);
});

app.ports.submitForm.subscribe(function (message) {
    document.getElementsByTagName("form").item(0).submit()
});
