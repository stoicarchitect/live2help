# Gap Brief drafts

The Sunday drafting task writes one file per issue here: `issue-N.json`. The workspace picks new files up every morning (and when someone presses
Check for new drafts on Marketing > Gap Briefs). Each brief then waits for approval by Daniel or Ella. Nothing sends until it is approved, and
the server never overwrites a brief that is already in the workspace.

Issue 1 sends on Tuesday 17 Nov 2026. A new issue sends every 14 days after that, always on a Tuesday at 10:00 UK time.
Draft on the Sunday before: issue = ((Tuesday - 2026-11-17) / 14 days) + 1.

## File format

```json
{
  "issue": 1,
  "sendDate": "2026-11-17",
  "briefs": [
    {
      "sector": "Engineering and Technical",
      "subject": "The Gap Brief: ...",
      "problemIds": [],
      "content": {
        "preheader": "Grey text next to the subject in an inbox",
        "headline": "White part of the headline",
        "headlineGold": "Gold part of the headline",
        "intro": "Text that follows 'Hi first name,' (starts lower case)",
        "numberValue": "+3%",
        "numberText": "What the number means. **bold** for emphasis.",
        "stateTitle": "1 Where things stand: heading",
        "statePoints": ["Two to four points. **bold** for the key phrase."],
        "futureTitle": "2 What the best employers do: heading",
        "futurePoints": ["Two to four points."],
        "gapText": "3 Mind the gap: the cost of waiting, two sentences.",
        "maths": "Salary only. **Bold** the inputs, ==gold== the result.",
        "checkTitle": "How wide is your gap?",
        "questions": ["Question 1", "Question 2", "Question 3"],
        "checkAsk": "",
        "myth": "Without quote marks",
        "reality": "One short sentence",
        "roleType": "engineers",
        "sources": "Publisher and report name, month year; Quick maths is salary only (...)."
      }
    }
  ]
}
```

`sector` must be exactly one of the twelve: Engineering and Technical; Manufacturing and Industrial; Procurement and Supply Chain; Sales and Business
Development; Accountancy and Finance; IT and Technology; Construction and Infrastructure; Health and Social Care; AI and Emerging Technologies;
HR and People Management; Corporate and Executive; Driving and Logistics. One brief per sector, all twelve in every issue.

## Rules (the workspace refuses to approve a brief that breaks the first four)

1. No fees, prices or percentages of salary for Live 2 Help. No placement stories. No "book a call". No Hiring Toolkit link.
2. No em dashes or en dashes anywhere. Use a simple hyphen or reword.
3. Exactly three gap check questions. `sources` is never empty.
4. No leftover placeholders in double curly brackets.
5. Every figure comes from a real, current, named source (published within roughly the last two months where possible) and is listed in `sources`.
   If no current figure can be found for a sector, say so in the subject-line notes of your report and use a qualitative number-free angle
   rather than inventing one.
6. The quick maths is salary only, with the assumption stated in `sources`.
7. Keep it to a two-minute read. Plain, confident, UK English. The reader's gap is the star, not Live 2 Help.
8. Draw the problem, impact and root cause from `gap-seed-problems.json` (the starting chart: six problems per sector, each with an id such as `eng-1`; the
   live chart is edited in the workspace and its ids are the same with a `gp-` prefix) and turn that problem's discovery questions into the three gap check questions.

## Rotation (briefs must not repeat)

- For each sector, look at every earlier `issue-N.json` in this folder and collect the `problemIds` used for that sector. Pick the problem whose id was used
  longest ago, or never. With six problems per sector a sector's angle comes round again after about three months, and by then its figures should be re-researched.
- Put the chosen id in the brief as `"problemIds": ["gp-eng-2"]` (the `gp-` prefix plus the id in the seed file). Always record it: the workspace uses it to show
  when each problem was last used.
- A new issue must also differ from the sector's previous issue in headline, number of the fortnight, myth and gap check questions. Never reuse a figure or source
  line from a previous issue unless the underlying figure has been re-checked and updated.
