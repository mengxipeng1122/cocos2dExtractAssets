document.addEventListener('DOMContentLoaded', function() {
    const splitter = document.getElementById('splitter');
    const leftPanel = document.querySelector('.left-panel');
    let isResizing = false;
    let lastX = 0;

    splitter.addEventListener('mousedown', function(e) {
        isResizing = true;
        lastX = e.clientX;
        document.body.style.cursor = 'col-resize';
    });

    document.addEventListener('mousemove', function(e) {
        if (!isResizing) return;

        const delta = e.clientX - lastX;
        const newWidth = leftPanel.offsetWidth + delta;

        // Check minimum and maximum constraints
        if (newWidth > 100 && newWidth < window.innerWidth * 0.8) {
            leftPanel.style.width = newWidth + 'px';
            lastX = e.clientX;
        }
    });

    document.addEventListener('mouseup', function() {
        isResizing = false;
        document.body.style.cursor = 'default';
    });
}); 