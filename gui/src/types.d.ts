// Declare global types for Electron window object
interface Window {
    electron: {
        ipcRenderer: {
            send: (channel: string, data?: any) => void;
            on: (channel: string, func: (...args: any[]) => void) => () => void;
        };
        window: {
            minimize: () => void;
            close: () => void;
        };
    };
}
