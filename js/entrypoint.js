let localData = null;

try {
    localData = localStorage.getItem("formFields");
} catch (error) {
    localData = null;
}

const app = Elm.Main.init(
    {
        flags: {
            serverData: window.serverData,
            localData: localData,
        }
    }
);

app.ports.saveToLocalStorage.subscribe(function (message) {
    try {
        localStorage.setItem("formFields", message);
    } catch (error) {
        // Draft persistence is best-effort; submit does not depend on it.
    }
});

app.ports.submitForm.subscribe(function () {
    const form = document.getElementsByTagName("form").item(0);

    if (form !== null) {
        form.submit();
    }
});
