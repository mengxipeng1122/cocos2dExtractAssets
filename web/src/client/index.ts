
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
                        const assetDetailsPlaceholder = document.getElementById('asset-details-placeholder') as HTMLElement;

                        function handle_png(data:ArrayBuffer){
                            // Check if the data is a PNG file by checking the PNG signature
                            const dataView = new DataView(data);
                            const pngSignature = [137, 80, 78, 71, 13, 10, 26, 10]; // PNG magic numbers
                            let isPNG = true;
                            
                            for (let i = 0; i < pngSignature.length; i++) {
                                if (dataView.getUint8(i) !== pngSignature[i]) {
                                    isPNG = false;
                                    break;
                                }
                            }

                            if (isPNG) {
                                // Convert ArrayBuffer to Blob and create object URL
                                const blob = new Blob([data], { type: 'image/png' });
                                const imageUrl = URL.createObjectURL(blob);

                                // Create and display the image
                                assetDetailsPlaceholder.innerHTML = ''; // Clear existing content

                                const img = document.createElement('img');
                                img.src = imageUrl;
                                img.style.maxWidth = '100%';
                                img.style.height = 'auto';
                                assetDetailsPlaceholder.appendChild(img);

                                // Clean up the object URL when the image loads
                                img.onload = () => {
                                    URL.revokeObjectURL(imageUrl);
                                };

                            }

                            return isPNG;
                        }

                        function handle_text(data:ArrayBuffer){
                            try {
                                // Create a UTF-8 decoder with strict error handling
                                const decoder = new TextDecoder('utf-8', { fatal: true });
                                const text = decoder.decode(data);
                                
                                // Additional check for non-UTF8 characters
                                if (text.includes('�')) {
                                    return false;
                                }
                                
                                assetDetailsPlaceholder.textContent = text;
                                return true;
                            } catch (e) {
                                return false;
                            }
                        }

                        function handle_hexdump(data:ArrayBuffer){
                            const hexdump = get_hexdump_from_arraybuffer(data);
                            assetDetailsPlaceholder.textContent = hexdump;
                            return true;
                        }


                            handle_png(data) 
                        ||  handle_text(data) 
                        ||  handle_hexdump(data);

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

    function make_search_assets_ui(){
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                const value = (e.target as HTMLInputElement).value;
                if (value.length > 2){
                    const searchTerm = value.toLowerCase();
                    const assetsList = document.getElementById('assets-list');
                    if (assetsList) {
                        const assetItems = assetsList.getElementsByClassName('asset-item');
                        Array.from(assetItems).forEach((item) => {
                            const text = item.textContent?.toLowerCase() || '';
                            if (text.includes(searchTerm)) {
                                (item as HTMLElement).style.display = '';
                            } else {
                                (item as HTMLElement).style.display = 'none';
                            }
                        });
                    }
                } else {
                    // Show all assets
                    const assetsList = document.getElementById('assets-list');
                    if (assetsList) {
                        assetsList.querySelectorAll('.asset-item').forEach(item => (item as HTMLElement).style.display = '');
                    }
                }
            });
        }
    }


    make_search_assets_ui();

    make_assets_list_ui();

    get_assets_list();
});
