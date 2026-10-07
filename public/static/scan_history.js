(function () {
    const storageKey = 'triVectorScanHistory';
    const maxEntries = 50;

    function readEntries() {
        const raw = localStorage.getItem(storageKey);
        if (!raw) return [];
        const entries = JSON.parse(raw);
        if (!Array.isArray(entries)) throw new Error('Saved history has an invalid format.');
        return entries.filter(entry =>
            entry &&
            typeof entry.date === 'string' &&
            typeof entry.type === 'string' &&
            typeof entry.target === 'string' &&
            typeof entry.result === 'string'
        ).slice(0, maxEntries);
    }

    function add(entry) {
        try {
            const entries = readEntries();
            entries.unshift({
                date: new Date().toISOString(),
                type: String(entry.type).slice(0, 40),
                target: String(entry.target).slice(0, 2048),
                result: String(entry.result).slice(0, 120),
                danger: entry.danger === true,
                confidence: Number.isFinite(entry.confidence) ? entry.confidence : null
            });
            localStorage.setItem(storageKey, JSON.stringify(entries.slice(0, maxEntries)));
        } catch (error) {
            console.warn('Could not save scan history in this browser.', error);
        }
    }

    function render() {
        const list = document.getElementById('history-list');
        if (!list) return;

        const empty = document.getElementById('history-empty');
        const message = document.getElementById('history-message');
        try {
            const entries = readEntries();
            empty.hidden = entries.length !== 0;
            list.replaceChildren();
            entries.forEach(entry => {
                const item = document.createElement('li');
                item.className = 'history-item';

                const heading = document.createElement('div');
                heading.className = 'history-item-heading';
                const type = document.createElement('strong');
                type.textContent = entry.type;
                const result = document.createElement('span');
                result.className = entry.danger
                    ? 'history-result alert-danger'
                    : 'history-result alert-success';
                result.textContent = entry.confidence === null
                    ? entry.result
                    : `${entry.result} · ${entry.confidence}% confidence`;
                heading.append(type, result);

                const target = document.createElement('p');
                target.className = 'history-target';
                target.textContent = entry.target;
                const date = document.createElement('time');
                date.className = 'history-date';
                date.dateTime = entry.date;
                const parsedDate = new Date(entry.date);
                date.textContent = Number.isNaN(parsedDate.getTime())
                    ? entry.date
                    : parsedDate.toLocaleString();
                item.append(heading, target, date);
                list.appendChild(item);
            });
            message.textContent = '';
        } catch (error) {
            message.textContent = 'Could not load saved history. Browser storage may be unavailable or corrupted.';
            console.error('Could not load scan history.', error);
        }
    }

    function clear() {
        const message = document.getElementById('history-message');
        try {
            localStorage.removeItem(storageKey);
            render();
        } catch (error) {
            message.textContent = 'Could not clear saved history. Browser storage may be unavailable.';
            console.error('Could not clear scan history.', error);
        }
    }

    window.ScanHistory = {add};
    document.addEventListener('DOMContentLoaded', () => {
        const clearButton = document.getElementById('clear-history-btn');
        if (clearButton) clearButton.addEventListener('click', clear);
        render();
    });
})();
