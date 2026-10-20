// Every user-visible string of the viewer (PRD-share §4.2, §4.4, §5.8).
// The viewer follows the browser language; English is the fallback.

const en = {
  join: "Join",
  joinPrompt: "Someone shared a PlexusTerm terminal with you.",
  waiting: "Waiting for the sharer to let you in",
  denied: "The sharer declined your request",
  ended: "The share has ended",
  offline: "The sharing computer went offline. The share has ended.",
  programExited: "The shared program exited",
  reconnecting: "Reconnecting…",
  sharerAway: "Sharing computer is unreachable — reconnecting…",
  nowViewOnly: "The sharer changed this share to view only",
  inputPaused: "The sharer paused viewer input",
  notFound: "This share has ended or the link is wrong. Ask for a new link.",
  incomplete: "This link is incomplete — the part after # is missing. Copy the whole link.",
  badKey: "This link's key is not valid. It may have been revoked.",
  full: "This share has reached its viewer limit.",
  unreachable: (relay: string) => `Can't reach ${relay}. Check your connection.`,
  unsupported: "This browser isn't supported. Use a current Chrome, Firefox or Safari.",
  outdated: "This viewer is out of date. Reload the page.",
  rateLimited: "Too many attempts. Try again in a minute.",
  viewOnly: "View only",
  canType: "Can type",
  endsAt: (time: string) => `Ends at ${time}`,
  trust: "Browser viewers trust the viewer page's server; for full end-to-end open in PlexusTerm.",
};

export type Strings = typeof en;

const es: Strings = {
  join: "Unirse",
  joinPrompt: "Alguien ha compartido contigo un terminal de PlexusTerm.",
  waiting: "Esperando a que quien comparte te deje entrar",
  denied: "Quien comparte ha rechazado tu solicitud",
  ended: "La sesión compartida ha terminado",
  offline: "El ordenador que comparte se ha desconectado. La sesión ha terminado.",
  programExited: "El programa compartido ha terminado",
  reconnecting: "Reconectando…",
  sharerAway: "No se puede contactar con el ordenador que comparte — reconectando…",
  nowViewOnly: "Quien comparte ha cambiado la sesión a solo lectura",
  inputPaused: "Quien comparte ha pausado la escritura de los espectadores",
  notFound: "Esta sesión ha terminado o el enlace no es correcto. Pide un enlace nuevo.",
  incomplete: "El enlace está incompleto: falta la parte que va después de #. Copia el enlace entero.",
  badKey: "La clave de este enlace no es válida. Puede que se haya revocado.",
  full: "Esta sesión ha alcanzado su límite de espectadores.",
  unreachable: (relay) => `No se puede contactar con ${relay}. Comprueba tu conexión.`,
  unsupported: "Este navegador no es compatible. Usa una versión actual de Chrome, Firefox o Safari.",
  outdated: "Este visor está desactualizado. Recarga la página.",
  rateLimited: "Demasiados intentos. Vuelve a probar en un minuto.",
  viewOnly: "Solo lectura",
  canType: "Puede escribir",
  endsAt: (time) => `Termina a las ${time}`,
  trust:
    "Los visores en el navegador confían en el servidor de la página del visor; para cifrado de extremo a extremo completo, ábrelo en PlexusTerm.",
};

export function strings(languages: readonly string[] = navigator.languages): Strings {
  for (const lang of languages) {
    const base = lang.toLowerCase().split("-")[0];
    if (base === "es") return es;
    if (base === "en") return en;
  }
  return en;
}
