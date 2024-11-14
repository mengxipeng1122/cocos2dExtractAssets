
import { get_hexdump_from_arraybuffer } from '../common';

document.addEventListener('DOMContentLoaded', () => {

    console.log('DOMContentLoaded');

    async function get_assets_list(){
        fetch('/api/invoke_frida_function', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ fun: 'getAssetsList', arg: [] }),
        })
        .then(response => response.json())
        .then((result:string[]) => {
            const assetsList = document.getElementById('assets-list');
            for (const asset of result) {
                const assetItem = document.createElement('div');
                assetItem.className = 'asset-item';
                assetItem.textContent = asset;

                assetItem.addEventListener('click', () => {
                    console.log(`Asset clicked: ${asset}`);
                    fetch('/api/invoke_frida_function', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ fun: 'getAssetBinary', arg: asset }),
                    }).then(response => response.arrayBuffer())
                    .then((data) => {
                        console.log(data.byteLength);
                        const hexdump = get_hexdump_from_arraybuffer(data);
                        console.log(hexdump);
                        const assetDetailsPlaceholder = document.getElementById('asset-details-placeholder') as HTMLElement;
                        assetDetailsPlaceholder.textContent = hexdump;
                    });
                });

                assetsList?.appendChild(assetItem);
            }
        });

    }

    async function make_assets_list_ui(){
        // Make splitter draggable
        const splitter = document.getElementById('splitter');
        const leftPanel = document.querySelector('.left-panel');
        let isResizing = false;
        let startX: number;
        let startWidth: number;

        splitter?.addEventListener('mousedown', (e) => {
            isResizing = true;
            startX = e.pageX;
            startWidth = (leftPanel as HTMLElement).offsetWidth;
        });

        document.addEventListener('mousemove', (e) => {
            if (!isResizing) return;
            
            const width = startWidth + (e.pageX - startX);
            if (leftPanel && width >= 200 && width <= 600) {
                (leftPanel as HTMLElement).style.width = `${width}px`;
            }
        });

        document.addEventListener('mouseup', () => {
            isResizing = false;
        });

        // Make assets list scrollable
        const assetsList = document.getElementById('assets-list');
        if (assetsList) {
            assetsList.style.overflowY = 'auto';
            assetsList.style.height = '100%';
        }


    }



    make_assets_list_ui();

    get_assets_list();
});
